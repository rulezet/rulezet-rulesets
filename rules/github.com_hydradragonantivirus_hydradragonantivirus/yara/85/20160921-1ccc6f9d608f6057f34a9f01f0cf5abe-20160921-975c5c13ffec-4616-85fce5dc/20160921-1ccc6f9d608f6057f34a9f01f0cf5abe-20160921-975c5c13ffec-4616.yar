rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_975c5c13ffec_4616 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_f1cc02f488792b7161849f8d15549315.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash3       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"

  strings:
    $s1 = "rn \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NBs\";})(),(f" ascii
    $s2 = "){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Lp\";})" ascii
    $s3 = "tion f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return" ascii
    $s4 = "f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"MD" ascii
    $s5 = "eturn \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SEo\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}