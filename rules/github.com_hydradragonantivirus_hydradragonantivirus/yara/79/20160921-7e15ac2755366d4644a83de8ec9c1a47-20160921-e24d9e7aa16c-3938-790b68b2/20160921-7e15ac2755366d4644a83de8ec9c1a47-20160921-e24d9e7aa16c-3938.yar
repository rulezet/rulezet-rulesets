rule _20160921_7e15ac2755366d4644a83de8ec9c1a47_20160921_e24d9e7aa16c_3938 {
  meta:
    description = "datamaliciousorder - from files 20160921_7e15ac2755366d4644a83de8ec9c1a47.js, 20160921_e24d9e7aa16c031b748aba6965b02dcb.js, 20160921_e71c0801261b54c695ea1dac03e838bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97eaf7c50f22bfc94f97a02e5e83a8f1fb3583717fb9f4a6666ae882ea4d6f55"
    hash2       = "c005836c702d4e1615fb302fc6f799ca097db41daa5b8cf6a66e8874a454d65b"
    hash3       = "c36b557af1bcfc43e39bfaabcd74048c39fc37b5ac0e9561b161a6d3d2e54e76"

  strings:
    $s1 = "turn \"Fv\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(f" ascii
    $s2 = "ction fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return" ascii
    $s3 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){retu" ascii
    $s4 = "fuck(){return \"QTc\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"B" ascii
    $s5 = "ion fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"" ascii
    $s6 = "ction fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}