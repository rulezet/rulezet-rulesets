rule _20160921_4c2bf112991da80cf65c9f462d7503be_20160921_515ffdda2060_5127 {
  meta:
    description = "datamaliciousorder - from files 20160921_4c2bf112991da80cf65c9f462d7503be.js, 20160921_515ffdda2060abfddd0b1faaa82a6279.js, 20160921_9c64236400e63181393ce4bc58f634a5.js, 20160921_cff8867bbb427ac014f0546c00ad8427.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2e5ee0ebdd9746b0055379071a47434cdd28be3788ad04e886f8bd01e0746c1"
    hash2       = "e66d45deceae626136192ed805b6d7d4dc1cb2be6956a53702353ef221f89c18"
    hash3       = "2b1d27f440a3f4232e02265ce38f6eee5a715bff67e056aca1a1c800909c0e37"
    hash4       = "80a0b2154f5b0c87fb7ba82fc32a74807761d038a93d6da45f835417e93af3ef"
    hash5       = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1 = "urn \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s2 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"" ascii
    $s3 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return " ascii
    $s4 = "turn \"Py\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s5 = "urn \"MIl\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}