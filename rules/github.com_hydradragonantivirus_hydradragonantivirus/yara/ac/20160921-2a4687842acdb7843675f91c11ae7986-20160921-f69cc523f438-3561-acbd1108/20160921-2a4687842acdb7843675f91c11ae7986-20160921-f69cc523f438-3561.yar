rule _20160921_2a4687842acdb7843675f91c11ae7986_20160921_f69cc523f438_3561 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4687842acdb7843675f91c11ae7986.js, 20160921_f69cc523f43841dbc6246209e09d2b8b.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b483b885082d284a148ab2a97b57881cd387b85b477025ad126d680e158bc62"
    hash2       = "82ee8104aecfd309a85de470b641e14f7ef67f3b3ec968ce41eade759620fd53"
    hash3       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1 = "ion fuck(){return \"Hs\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s2 = "ck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jo\"" ascii
    $s3 = "n \"Fv\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(fun" ascii
    $s4 = "(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Xg\";})(),(function fuck()" ascii
    $s5 = "eturn \"Hs\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s6 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MUs\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}