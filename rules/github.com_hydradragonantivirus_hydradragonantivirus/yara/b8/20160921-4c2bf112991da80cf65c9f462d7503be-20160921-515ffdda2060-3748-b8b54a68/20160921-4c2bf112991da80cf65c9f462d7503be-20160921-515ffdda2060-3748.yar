rule _20160921_4c2bf112991da80cf65c9f462d7503be_20160921_515ffdda2060_3748 {
  meta:
    description = "datamaliciousorder - from files 20160921_4c2bf112991da80cf65c9f462d7503be.js, 20160921_515ffdda2060abfddd0b1faaa82a6279.js, 20160921_64fd82bf037f1ee6b74269456349f2e6.js, 20160921_9c64236400e63181393ce4bc58f634a5.js, 20160921_cff8867bbb427ac014f0546c00ad8427.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2e5ee0ebdd9746b0055379071a47434cdd28be3788ad04e886f8bd01e0746c1"
    hash2       = "e66d45deceae626136192ed805b6d7d4dc1cb2be6956a53702353ef221f89c18"
    hash3       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"
    hash4       = "2b1d27f440a3f4232e02265ce38f6eee5a715bff67e056aca1a1c800909c0e37"
    hash5       = "80a0b2154f5b0c87fb7ba82fc32a74807761d038a93d6da45f835417e93af3ef"

  strings:
    $s1 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Jg\";})(),(function" ascii
    $s2 = "uck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IP" ascii
    $s3 = "ction fuck(){return \"Yk\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii
    $s4 = "(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(" ascii
    $s5 = ")(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"MIl\";})(),(function fuc" ascii
    $s6 = "turn \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}