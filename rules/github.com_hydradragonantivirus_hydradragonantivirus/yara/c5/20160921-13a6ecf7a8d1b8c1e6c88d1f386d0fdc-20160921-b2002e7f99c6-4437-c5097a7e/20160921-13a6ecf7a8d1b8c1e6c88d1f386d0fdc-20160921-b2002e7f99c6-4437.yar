rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_b2002e7f99c6_4437 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"

  strings:
    $s1 = "})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s2 = "nction f000(){return \"Do\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s3 = "\"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(func" ascii
    $s4 = ",(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"RPt\";})(),(function f000(){" ascii
    $s5 = "Gn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}