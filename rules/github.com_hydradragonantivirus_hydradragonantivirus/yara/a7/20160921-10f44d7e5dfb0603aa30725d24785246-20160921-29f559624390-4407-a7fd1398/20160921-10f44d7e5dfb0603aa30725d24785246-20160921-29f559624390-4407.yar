rule _20160921_10f44d7e5dfb0603aa30725d24785246_20160921_29f559624390_4407 {
  meta:
    description = "datamaliciousorder - from files 20160921_10f44d7e5dfb0603aa30725d24785246.js, 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_a6679b5a153c4bb3f7cb9fe7c02dc710.js, 20160921_ba12dcdd1588a0048542bf1b103073ef.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ded66def256e0559ce1d6d20e6f8663edec045a58bb8ef0ec1038fbd91f7c7c1"
    hash2       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash3       = "c54f97191e0c15791315cc1823b0fbce23679bebe5b1ce5c2b6b4895074c1121"
    hash4       = "18a1f3c65d9893a27783cb78ff5cd36c757196e35be1977f03c68231e20d9b44"
    hash5       = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"

  strings:
    $s1 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ff\";})(),(function fuck(){return \"MBg\";})(),(function fu" ascii
    $s2 = "),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(" ascii
    $s3 = "),(function fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(" ascii
    $s4 = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(fun" ascii
    $s5 = "uck(){return \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}