rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_0ef3d27b58b6_4261 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_22511056ddb6d59ffb3e56c3b7382182.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash3       = "1a5f7b2bfdf24defc0d363114441d0c0a0452fd599bf21d359b1b5f068dfc567"

  strings:
    $s1 = "(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(" ascii
    $s2 = "eturn \"TTs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})()," ascii
    $s3 = "(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";" ascii
    $s4 = "rn \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s5 = "Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}