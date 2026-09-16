rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_35d4c12af7a9_4430 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_35d4c12af7a9481959a41a055c396673.js, 20160921_64fd82bf037f1ee6b74269456349f2e6.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "1c2412951fad30bb8b34aca279acd07c03a437936261b0d90334331b98cf1e99"
    hash3       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"
    hash4       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash5       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"

  strings:
    $s1 = " fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s2 = "k(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XFd" ascii
    $s3 = "{return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s4 = "eturn \"Ot\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Jo\";})()," ascii
    $s5 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ik\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}