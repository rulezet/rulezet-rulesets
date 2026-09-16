rule _20160921_5e30fe0c691277f3c6d0814d796ba918_20160921_627f79d589bd_3822 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e30fe0c691277f3c6d0814d796ba918.js, 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_6c49e33f1abb3ca2b0ff12a4878e38c8.js, 20160921_c779962dc8b38bbb280b695e631131fa.js, 20160921_ec2d2710e9217c2f295a4b410a623d5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cac2594d8c0286d3110fd3705816d41052df49790da39881cedd79b8cb5c6ed"
    hash2       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash3       = "b2c5f6e5a1ebce2cb0eb54f0d28ea21ab88b07dc646376bb3fc5ce29af1615aa"
    hash4       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"
    hash5       = "efabdabbb3a7d8e1d713826868acadadd9ab03b4cb57f3799d6add11f212fdd9"

  strings:
    $s1 = "n fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"" ascii
    $s2 = "{return \"IKv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";}" ascii
    $s3 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MB" ascii
    $s4 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s5 = "return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})()" ascii
    $s6 = "{return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}