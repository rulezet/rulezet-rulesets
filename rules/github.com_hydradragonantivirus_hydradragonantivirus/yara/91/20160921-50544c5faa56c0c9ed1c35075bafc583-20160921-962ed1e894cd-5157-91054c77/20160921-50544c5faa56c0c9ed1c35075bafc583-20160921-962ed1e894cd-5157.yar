rule _20160921_50544c5faa56c0c9ed1c35075bafc583_20160921_962ed1e894cd_5157 {
  meta:
    description = "datamaliciousorder - from files 20160921_50544c5faa56c0c9ed1c35075bafc583.js, 20160921_962ed1e894cd91f421ad984310ce3140.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"
    hash2       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"

  strings:
    $s1 = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"YQt\";})(" ascii
    $s2 = "s\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(functio" ascii
    $s3 = "),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(" ascii
    $s4 = "eturn \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(" ascii
    $s5 = "{return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}