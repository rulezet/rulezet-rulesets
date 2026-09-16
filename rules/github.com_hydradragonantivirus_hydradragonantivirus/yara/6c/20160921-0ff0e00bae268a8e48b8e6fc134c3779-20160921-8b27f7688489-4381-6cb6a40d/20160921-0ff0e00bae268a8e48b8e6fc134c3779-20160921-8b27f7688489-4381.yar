rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_8b27f7688489_4381 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash3       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1 = "})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000" ascii
    $s2 = "return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})()," ascii
    $s3 = "nction f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s4 = "(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){r" ascii
    $s5 = "eturn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}