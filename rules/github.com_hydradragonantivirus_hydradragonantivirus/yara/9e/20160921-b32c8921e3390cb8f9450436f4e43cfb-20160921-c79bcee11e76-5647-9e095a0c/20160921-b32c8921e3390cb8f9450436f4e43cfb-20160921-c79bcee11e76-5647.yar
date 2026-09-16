rule _20160921_b32c8921e3390cb8f9450436f4e43cfb_20160921_c79bcee11e76_5647 {
  meta:
    description = "datamaliciousorder - from files 20160921_b32c8921e3390cb8f9450436f4e43cfb.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"
    hash2       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"

  strings:
    $s1 = "\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"PTs\";})(),(function" ascii
    $s2 = "ction f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s3 = "function f000(){return \"KXg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"KXg\";})(),(function f000(){r" ascii
    $s4 = "Na\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s5 = "return \"BIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"NBs\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}