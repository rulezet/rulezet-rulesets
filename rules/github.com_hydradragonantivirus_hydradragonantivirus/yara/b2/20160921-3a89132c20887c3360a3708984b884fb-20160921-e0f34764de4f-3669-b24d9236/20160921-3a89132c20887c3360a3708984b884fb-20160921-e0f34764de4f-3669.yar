rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_e0f34764de4f_3669 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_e0f34764de4fcb908eef371ab4011f31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "de457f8d789ffcd672900ad06037697526230f620a01d113732fa3683b1604b1"

  strings:
    $s1 = "00(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl" ascii
    $s2 = "\"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(funct" ascii
    $s3 = "Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(functio" ascii
    $s4 = "eturn \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(" ascii
    $s5 = "(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})" ascii
    $s6 = "turn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}