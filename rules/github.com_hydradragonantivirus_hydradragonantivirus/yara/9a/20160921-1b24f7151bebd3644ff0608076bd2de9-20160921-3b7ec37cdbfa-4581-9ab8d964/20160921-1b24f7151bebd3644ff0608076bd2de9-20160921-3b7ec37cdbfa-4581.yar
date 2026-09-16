rule _20160921_1b24f7151bebd3644ff0608076bd2de9_20160921_3b7ec37cdbfa_4581 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b24f7151bebd3644ff0608076bd2de9.js, 20160921_3b7ec37cdbfac434e32c8743c60228af.js, 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_91424e3b4f105c156aa0fa6f22c2306f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33f3c9ce370f10b37d492f9d2cda8602f5d90eb1573205e1a4da03da8066ff45"
    hash2       = "86390741cf6e610c2e526db749631548b514c268decade5a5870edfebb141d4b"
    hash3       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash4       = "b4a035e38404ad09be99953980865cdbcda5dd05b664dff96722afb53b0c9e29"

  strings:
    $s1 = "fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb" ascii
    $s2 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s3 = ";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function f" ascii
    $s4 = "(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){r" ascii
    $s5 = "n fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}