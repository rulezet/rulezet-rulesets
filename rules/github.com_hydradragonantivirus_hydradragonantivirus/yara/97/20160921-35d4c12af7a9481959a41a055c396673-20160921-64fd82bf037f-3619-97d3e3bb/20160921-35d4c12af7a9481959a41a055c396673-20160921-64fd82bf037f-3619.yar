rule _20160921_35d4c12af7a9481959a41a055c396673_20160921_64fd82bf037f_3619 {
  meta:
    description = "datamaliciousorder - from files 20160921_35d4c12af7a9481959a41a055c396673.js, 20160921_64fd82bf037f1ee6b74269456349f2e6.js, 20160921_65d76a5539546b98145997b9a44c1a09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2412951fad30bb8b34aca279acd07c03a437936261b0d90334331b98cf1e99"
    hash2       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"
    hash3       = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"

  strings:
    $s1 = "return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s2 = "\"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(func" ascii
    $s3 = "turn \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(" ascii
    $s4 = " fuck(){return \"Np\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GN" ascii
    $s5 = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){retur" ascii
    $s6 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Xg" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}