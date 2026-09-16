rule _20160921_4f8422c91e79e3073e201b0b279b1fbb_20160921_65d76a553954_5150 {
  meta:
    description = "datamaliciousorder - from files 20160921_4f8422c91e79e3073e201b0b279b1fbb.js, 20160921_65d76a5539546b98145997b9a44c1a09.js, 20160921_73e0cbee151147d27e01ecc015f640b4.js, 20160921_c979e38640433b8c93e1c145417c85cb.js, 20160921_de770f0ed114194a1a9d5e965c4fe675.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1cc54af4d213d0cd37c81b29d25c29bf00892e3458ef2e236563c69fd58b94a"
    hash2       = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"
    hash3       = "0ad4b632b07e5e4526b874097c116e5183b155ec4b9cf40e3f13ece0ce027344"
    hash4       = "62a468202853ba6a8adb456e8c12b66f8794360c094a85e6d4d2cf43d13a75ce"
    hash5       = "57a3f4ba7362a09dfecfe27f6b8517c8290bc04a7020f4bbe4e9200a42655be0"

  strings:
    $s1 = "){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})" ascii
    $s2 = "rn \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(" ascii
    $s3 = " fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"I" ascii
    $s4 = "turn \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Jo\";})(),(" ascii
    $s5 = "fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}