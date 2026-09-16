rule _20160921_42353ce257534ed06a8c73cebdde12dc_20160921_78bd4256ddc0_5045 {
  meta:
    description = "datamaliciousorder - from files 20160921_42353ce257534ed06a8c73cebdde12dc.js, 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"
    hash2       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"

  strings:
    $s1 = "unction fuck(){return \"Nm\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retu" ascii
    $s2 = "ction fuck(){return \"Mw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s3 = "uck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"RAi" ascii
    $s4 = "(function fuck(){return \"OQr\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){r" ascii
    $s5 = "k(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}