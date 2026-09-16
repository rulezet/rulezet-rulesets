rule _20160921_4c22609fd7310d7f415ca007620a244b_20160921_8a6f0879f250_3743 {
  meta:
    description = "datamaliciousorder - from files 20160921_4c22609fd7310d7f415ca007620a244b.js, 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"
    hash2       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash3       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash4       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"

  strings:
    $s1 = "ction f000(){return \"QDg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oh\";})(),(function f000(){return" ascii
    $s2 = "rn \"HJm\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s3 = "eturn \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Km\";})()," ascii
    $s4 = "n f000(){return \"MDb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"" ascii
    $s5 = "})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"MJq\";})(),(function f0" ascii
    $s6 = "on f000(){return \"Qa\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}