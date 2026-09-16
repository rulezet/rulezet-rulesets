rule _20160921_a96b471e778a8101c168e06727d930fb_20160921_e78383c7f2f1_2557 {
  meta:
    description = "datamaliciousorder - from files 20160921_a96b471e778a8101c168e06727d930fb.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"
    hash2       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"

  strings:
    $s1 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Wo\";" ascii
    $s2 = "u\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"KVh\";})(),(functio" ascii
    $s3 = "\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function f" ascii
    $s4 = ";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"AUx\";})(),(function fuc" ascii
    $s5 = "uck(){return \"XCr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"GNm" ascii
    $s6 = "\"PDf\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s7 = "(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"YQt\";})(),(function fuck" ascii
    $s8 = "n fuck(){return \"CCb\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}