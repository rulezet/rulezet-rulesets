rule _20160921_22511056ddb6d59ffb3e56c3b7382182_20160921_d414cec9501c_4711 {
  meta:
    description = "datamaliciousorder - from files 20160921_22511056ddb6d59ffb3e56c3b7382182.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a5f7b2bfdf24defc0d363114441d0c0a0452fd599bf21d359b1b5f068dfc567"
    hash2       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"

  strings:
    $s1 = "){return \"XHj\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";}" ascii
    $s2 = ",(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck()" ascii
    $s3 = "(function fuck(){return \"Et\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){re" ascii
    $s4 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){retu" ascii
    $s5 = "on fuck(){return \"Vf\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}