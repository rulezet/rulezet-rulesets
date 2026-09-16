rule _20160921_3214ea252f2a25e018a03ee43ce952f5_20160921_32a3b245a67c_1470 {
  meta:
    description = "datamaliciousorder - from files 20160921_3214ea252f2a25e018a03ee43ce952f5.js, 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e406c80b4ad80ad1898c09cec0694086bfb24caedb8bc3bb213513d0b4232bd3"
    hash2       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash3       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"

  strings:
    $s1  = "ction fuck(){return \"YQt\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s2  = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s3  = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"SUi\";})" ascii
    $s4  = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"" ascii
    $s5  = "(function fuck(){return \"Xw\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){r" ascii
    $s6  = "unction fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){retu" ascii
    $s7  = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ug\";})(),(function fuck()" ascii
    $s8  = "return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})" ascii
    $s9  = "ck(){return \"UXf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Ug\"" ascii
    $s10 = "tion fuck(){return \"XHj\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s11 = ";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"QTc\";})(),(function fu" ascii
    $s12 = "eturn \"Fv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s13 = "ction fuck(){return \"XHj\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}