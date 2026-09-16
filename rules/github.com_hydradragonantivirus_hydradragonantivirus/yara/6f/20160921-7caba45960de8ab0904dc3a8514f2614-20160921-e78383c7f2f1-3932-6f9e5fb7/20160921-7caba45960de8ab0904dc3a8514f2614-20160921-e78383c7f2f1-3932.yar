rule _20160921_7caba45960de8ab0904dc3a8514f2614_20160921_e78383c7f2f1_3932 {
  meta:
    description = "datamaliciousorder - from files 20160921_7caba45960de8ab0904dc3a8514f2614.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f07b11e4aaeb00f3fa8863261ca37d382057c7775579fae2a5744dcfdb99cd95"
    hash2       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"

  strings:
    $s1 = "){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";" ascii
    $s2 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){" ascii
    $s3 = "){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";}" ascii
    $s4 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return" ascii
    $s5 = "ion fuck(){return \"Dc\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s6 = "nction fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}