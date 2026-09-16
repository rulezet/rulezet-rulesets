rule _20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347_20160921_abc9044816c2_5593 {
  meta:
    description = "datamaliciousorder - from files 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js, 20160921_abc9044816c2455dc24ac338746b6bd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"
    hash2       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"

  strings:
    $s1 = "){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Np\";}" ascii
    $s2 = "p\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function" ascii
    $s3 = "ck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";" ascii
    $s4 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){r" ascii
    $s5 = "n \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}