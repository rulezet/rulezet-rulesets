rule _20160921_8b27f7688489936aa1cc7fded52f4a64_20160921_c79bcee11e76_3085 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash2       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"
    hash3       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1 = "f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yz" ascii
    $s2 = "})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"PTs\";})(),(function f0" ascii
    $s3 = ";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\";})(),(function f" ascii
    $s4 = "turn \"BIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"NBs\";})(),(" ascii
    $s5 = "n f000(){return \"DNa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"M" ascii
    $s6 = "n f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s7 = "PTs\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}