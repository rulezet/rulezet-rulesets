rule _20160921_262709d34b477380050375a3b5b2833b_20160921_e0f7b2a32a09_4751 {
  meta:
    description = "datamaliciousorder - from files 20160921_262709d34b477380050375a3b5b2833b.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2738de24af2af834f5ce43b4e99137d47cd1993ec0b6dc3c1071deb99efcd62c"
    hash2       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1 = "(function fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){r" ascii
    $s2 = "(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck()" ascii
    $s3 = "\"Xg\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(funct" ascii
    $s4 = "n fuck(){return \"OQr\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"" ascii
    $s5 = "(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}