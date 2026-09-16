rule _20160921_4bad0ae96eb9fc3a1c603846a44ffe13_20160921_8f9d19bbb031_5117 {
  meta:
    description = "datamaliciousorder - from files 20160921_4bad0ae96eb9fc3a1c603846a44ffe13.js, 20160921_8f9d19bbb031c21665ebbafad8d5ab55.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a99f235f58613323f5c58def3503d47959f4a77f0697e30c75b6d221c4b40806"
    hash2       = "b4039cc962a684523fe76faba20cbc27d33e0e6b0c86feb67e04127cf37a2fc4"

  strings:
    $s1 = "on fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"" ascii
    $s2 = "uck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DH" ascii
    $s3 = "eturn \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})()," ascii
    $s4 = "rn \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(fu" ascii
    $s5 = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}