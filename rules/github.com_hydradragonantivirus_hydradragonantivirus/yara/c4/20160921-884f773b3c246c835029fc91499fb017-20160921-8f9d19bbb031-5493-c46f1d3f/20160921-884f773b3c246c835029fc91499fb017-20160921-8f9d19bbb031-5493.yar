rule _20160921_884f773b3c246c835029fc91499fb017_20160921_8f9d19bbb031_5493 {
  meta:
    description = "datamaliciousorder - from files 20160921_884f773b3c246c835029fc91499fb017.js, 20160921_8f9d19bbb031c21665ebbafad8d5ab55.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"
    hash2       = "b4039cc962a684523fe76faba20cbc27d33e0e6b0c86feb67e04127cf37a2fc4"

  strings:
    $s1 = "u\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"LGo\";})(),(function" ascii
    $s2 = "nction fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){ret" ascii
    $s3 = "function fuck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s4 = "Dy\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(functi" ascii
    $s5 = "eturn \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}