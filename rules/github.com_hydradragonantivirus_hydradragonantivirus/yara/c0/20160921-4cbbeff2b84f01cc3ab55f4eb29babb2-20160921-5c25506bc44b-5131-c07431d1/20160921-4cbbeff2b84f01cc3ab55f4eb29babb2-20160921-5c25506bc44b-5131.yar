rule _20160921_4cbbeff2b84f01cc3ab55f4eb29babb2_20160921_5c25506bc44b_5131 {
  meta:
    description = "datamaliciousorder - from files 20160921_4cbbeff2b84f01cc3ab55f4eb29babb2.js, 20160921_5c25506bc44b50a0c8028dec6521139d.js, 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "698c46439ef391a98b04ac1a2759ff8a84b30a9c444a7575c5290eb0aa4b66b9"
    hash2       = "b6178db9a292199c6992547ad654bf7056fa7f33310f29988e468f0cad5ed707"
    hash3       = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"

  strings:
    $s1 = "(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck()" ascii
    $s2 = "tion fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return " ascii
    $s3 = " \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(funct" ascii
    $s4 = "(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})" ascii
    $s5 = " fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IP" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}