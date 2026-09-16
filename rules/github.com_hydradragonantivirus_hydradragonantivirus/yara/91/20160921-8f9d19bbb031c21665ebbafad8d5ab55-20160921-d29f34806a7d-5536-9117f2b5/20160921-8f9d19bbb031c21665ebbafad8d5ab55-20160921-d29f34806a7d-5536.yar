rule _20160921_8f9d19bbb031c21665ebbafad8d5ab55_20160921_d29f34806a7d_5536 {
  meta:
    description = "datamaliciousorder - from files 20160921_8f9d19bbb031c21665ebbafad8d5ab55.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4039cc962a684523fe76faba20cbc27d33e0e6b0c86feb67e04127cf37a2fc4"
    hash2       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"

  strings:
    $s1 = "){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MBg\";" ascii
    $s2 = ")(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Vb\";})(),(function fuck" ascii
    $s3 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Ff\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii
    $s4 = "n fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s5 = "uck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"OP" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}