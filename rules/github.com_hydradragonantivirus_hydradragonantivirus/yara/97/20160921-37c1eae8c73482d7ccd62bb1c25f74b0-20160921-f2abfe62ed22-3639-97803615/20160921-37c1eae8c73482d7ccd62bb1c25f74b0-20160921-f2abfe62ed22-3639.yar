rule _20160921_37c1eae8c73482d7ccd62bb1c25f74b0_20160921_f2abfe62ed22_3639 {
  meta:
    description = "datamaliciousorder - from files 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js, 20160921_f2abfe62ed227fb547869419a6d3af3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"
    hash2       = "843cfa29e93bfa9adfe4410735aacbf939d01a404dc3c507c0562f478b65086f"

  strings:
    $s1 = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii
    $s2 = "(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";" ascii
    $s3 = "fuck(){return \"Et\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MBg" ascii
    $s4 = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retur" ascii
    $s5 = "nction fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii
    $s6 = "ck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}