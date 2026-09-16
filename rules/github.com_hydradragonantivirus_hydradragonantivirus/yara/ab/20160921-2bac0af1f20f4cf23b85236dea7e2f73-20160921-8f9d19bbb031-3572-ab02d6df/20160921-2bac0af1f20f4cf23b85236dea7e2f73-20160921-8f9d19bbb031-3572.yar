rule _20160921_2bac0af1f20f4cf23b85236dea7e2f73_20160921_8f9d19bbb031_3572 {
  meta:
    description = "datamaliciousorder - from files 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js, 20160921_8f9d19bbb031c21665ebbafad8d5ab55.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"
    hash2       = "b4039cc962a684523fe76faba20cbc27d33e0e6b0c86feb67e04127cf37a2fc4"

  strings:
    $s1 = "\"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(fun" ascii
    $s2 = "unction fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retu" ascii
    $s3 = ")(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s4 = " \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(fun" ascii
    $s5 = "(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";}" ascii
    $s6 = "uck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}