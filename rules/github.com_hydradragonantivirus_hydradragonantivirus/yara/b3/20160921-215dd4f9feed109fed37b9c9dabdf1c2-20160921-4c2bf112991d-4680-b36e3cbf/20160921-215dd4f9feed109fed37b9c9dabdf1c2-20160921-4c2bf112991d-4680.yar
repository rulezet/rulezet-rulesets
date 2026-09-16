rule _20160921_215dd4f9feed109fed37b9c9dabdf1c2_20160921_4c2bf112991d_4680 {
  meta:
    description = "datamaliciousorder - from files 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_4c2bf112991da80cf65c9f462d7503be.js, 20160921_515ffdda2060abfddd0b1faaa82a6279.js, 20160921_9c64236400e63181393ce4bc58f634a5.js, 20160921_b0c04db09e980eb82ccee9091ca50467.js, 20160921_cff8867bbb427ac014f0546c00ad8427.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash2       = "f2e5ee0ebdd9746b0055379071a47434cdd28be3788ad04e886f8bd01e0746c1"
    hash3       = "e66d45deceae626136192ed805b6d7d4dc1cb2be6956a53702353ef221f89c18"
    hash4       = "2b1d27f440a3f4232e02265ce38f6eee5a715bff67e056aca1a1c800909c0e37"
    hash5       = "9e020a4a8174eebc9bdfd2c370a1a8a86e255e968f9dc218329e9d5912ba227b"
    hash6       = "80a0b2154f5b0c87fb7ba82fc32a74807761d038a93d6da45f835417e93af3ef"

  strings:
    $s1 = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return" ascii
    $s2 = "urn \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(f" ascii
    $s3 = "eturn \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})()" ascii
    $s4 = "\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s5 = "n \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}