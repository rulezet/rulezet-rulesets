rule _20160921_619a314e9bcca286c046dff250b54b6b_20160921_8a6f0879f250_3847 {
  meta:
    description = "datamaliciousorder - from files 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash2       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash3       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash4       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"

  strings:
    $s1 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NYh\";})(),(function f00" ascii
    $s2 = ",(function f000(){return \"Tn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Br\";})(),(function f000(){r" ascii
    $s3 = " f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv" ascii
    $s4 = "})(),(function f000(){return \"Sv\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"MDb\";})(),(function f00" ascii
    $s5 = "WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(funct" ascii
    $s6 = "(function f000(){return \"TKp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"MDb\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}