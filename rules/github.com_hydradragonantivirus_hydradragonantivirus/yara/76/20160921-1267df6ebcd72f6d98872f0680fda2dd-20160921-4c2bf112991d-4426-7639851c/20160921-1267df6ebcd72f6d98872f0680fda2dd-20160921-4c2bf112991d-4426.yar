rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_4c2bf112991d_4426 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_4c2bf112991da80cf65c9f462d7503be.js, 20160921_515ffdda2060abfddd0b1faaa82a6279.js, 20160921_9c64236400e63181393ce4bc58f634a5.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js, 20160921_b0c04db09e980eb82ccee9091ca50467.js, 20160921_cff8867bbb427ac014f0546c00ad8427.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "f2e5ee0ebdd9746b0055379071a47434cdd28be3788ad04e886f8bd01e0746c1"
    hash3       = "e66d45deceae626136192ed805b6d7d4dc1cb2be6956a53702353ef221f89c18"
    hash4       = "2b1d27f440a3f4232e02265ce38f6eee5a715bff67e056aca1a1c800909c0e37"
    hash5       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash6       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"
    hash7       = "9e020a4a8174eebc9bdfd2c370a1a8a86e255e968f9dc218329e9d5912ba227b"
    hash8       = "80a0b2154f5b0c87fb7ba82fc32a74807761d038a93d6da45f835417e93af3ef"

  strings:
    $s1 = "eturn \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()," ascii
    $s2 = "z\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Qh\";})(),(function" ascii
    $s3 = "(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";" ascii
    $s4 = " \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(fun" ascii
    $s5 = ",(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}