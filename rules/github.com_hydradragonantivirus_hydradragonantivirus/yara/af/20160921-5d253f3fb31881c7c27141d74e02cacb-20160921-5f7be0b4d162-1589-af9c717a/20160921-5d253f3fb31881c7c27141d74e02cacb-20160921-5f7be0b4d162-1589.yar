rule _20160921_5d253f3fb31881c7c27141d74e02cacb_20160921_5f7be0b4d162_1589 {
  meta:
    description = "datamaliciousorder - from files 20160921_5d253f3fb31881c7c27141d74e02cacb.js, 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae85fe56260e8c9a1243da145f7594a08ac59bd50027af5e54b6d04e82f44e88"
    hash2       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"

  strings:
    $s1  = ",(function fuck(){return \"Wo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){r" ascii
    $s2  = "(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";" ascii
    $s3  = "urn \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Fv\";})(),(fu" ascii
    $s4  = "return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s5  = "fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"O" ascii
    $s6  = "){return \"Ot\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s7  = "),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck()" ascii
    $s8  = "ck(){return \"DWe\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s9  = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return " ascii
    $s10 = "k(){return \"MIl\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Hs\";" ascii
    $s11 = " \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(functi" ascii
    $s12 = "ion fuck(){return \"Oh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}