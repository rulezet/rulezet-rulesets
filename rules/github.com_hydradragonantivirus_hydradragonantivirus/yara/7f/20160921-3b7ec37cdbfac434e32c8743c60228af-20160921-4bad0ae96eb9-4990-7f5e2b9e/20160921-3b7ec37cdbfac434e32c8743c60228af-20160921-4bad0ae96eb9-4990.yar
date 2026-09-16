rule _20160921_3b7ec37cdbfac434e32c8743c60228af_20160921_4bad0ae96eb9_4990 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b7ec37cdbfac434e32c8743c60228af.js, 20160921_4bad0ae96eb9fc3a1c603846a44ffe13.js, 20160921_884f773b3c246c835029fc91499fb017.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86390741cf6e610c2e526db749631548b514c268decade5a5870edfebb141d4b"
    hash2       = "a99f235f58613323f5c58def3503d47959f4a77f0697e30c75b6d221c4b40806"
    hash3       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"

  strings:
    $s1 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){retu" ascii
    $s2 = "rn \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s3 = "})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(function fuck" ascii
    $s4 = "\"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(funct" ascii
    $s5 = "(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}