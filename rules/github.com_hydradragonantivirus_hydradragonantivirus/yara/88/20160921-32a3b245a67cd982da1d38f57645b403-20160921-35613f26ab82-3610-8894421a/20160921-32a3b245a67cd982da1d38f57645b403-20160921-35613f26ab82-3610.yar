rule _20160921_32a3b245a67cd982da1d38f57645b403_20160921_35613f26ab82_3610 {
  meta:
    description = "datamaliciousorder - from files 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js, 20160921_4031e49cbb76e44dd58fa572b63a00c7.js, 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash2       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"
    hash3       = "42519dff3fd2ed2dc9bcd0f12a16fe310be93f90efd5d40110f336dc5010d050"
    hash4       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"

  strings:
    $s1 = "uck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Za" ascii
    $s2 = "n \"EHo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s3 = "return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})()," ascii
    $s4 = "n fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s5 = "nction fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){retu" ascii
    $s6 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"To\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}