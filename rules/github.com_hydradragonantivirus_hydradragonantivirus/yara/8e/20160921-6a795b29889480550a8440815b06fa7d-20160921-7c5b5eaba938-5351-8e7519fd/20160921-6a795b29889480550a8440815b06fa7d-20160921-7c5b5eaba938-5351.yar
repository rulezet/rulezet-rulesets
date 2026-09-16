rule _20160921_6a795b29889480550a8440815b06fa7d_20160921_7c5b5eaba938_5351 {
  meta:
    description = "datamaliciousorder - from files 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash2       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"

  strings:
    $s1 = "turn \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})()" ascii
    $s2 = "unction fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){retu" ascii
    $s3 = "){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})" ascii
    $s4 = "(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s5 = "function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}