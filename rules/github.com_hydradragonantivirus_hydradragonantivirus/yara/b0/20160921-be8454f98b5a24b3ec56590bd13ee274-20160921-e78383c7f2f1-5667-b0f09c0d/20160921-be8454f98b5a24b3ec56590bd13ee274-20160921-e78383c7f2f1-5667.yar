rule _20160921_be8454f98b5a24b3ec56590bd13ee274_20160921_e78383c7f2f1_5667 {
  meta:
    description = "datamaliciousorder - from files 20160921_be8454f98b5a24b3ec56590bd13ee274.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"
    hash2       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"

  strings:
    $s1 = "n \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Ik\";})(),(func" ascii
    $s2 = "(){return \"GNm\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";" ascii
    $s3 = "k(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\"" ascii
    $s4 = "unction fuck(){return \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){re" ascii
    $s5 = "),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}