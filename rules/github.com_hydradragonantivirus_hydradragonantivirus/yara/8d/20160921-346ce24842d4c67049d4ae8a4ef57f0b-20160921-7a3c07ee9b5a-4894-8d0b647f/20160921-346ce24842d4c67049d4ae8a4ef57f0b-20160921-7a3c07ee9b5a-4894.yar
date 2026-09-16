rule _20160921_346ce24842d4c67049d4ae8a4ef57f0b_20160921_7a3c07ee9b5a_4894 {
  meta:
    description = "datamaliciousorder - from files 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js, 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"
    hash2       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"

  strings:
    $s1 = "nction f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s2 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){retur" ascii
    $s3 = "0(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";" ascii
    $s4 = "\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function " ascii
    $s5 = "f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"M" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}