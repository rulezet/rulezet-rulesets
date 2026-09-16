rule _20160921_4d30edc3a4e3226feee5b6289df9e399_20160921_78bd4256ddc0_3757 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash2       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"

  strings:
    $s1 = "fuck(){return \"DWe\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MO" ascii
    $s2 = "urn \"OQr\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s3 = "{return \"Dc\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Zy\";})()" ascii
    $s4 = " \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Et\";})(),(fun" ascii
    $s5 = "(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\"" ascii
    $s6 = "Pu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}