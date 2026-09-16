rule _20160921_2b38530ecae3735e98453e56dd7a0292_20160921_a210d5e93bf8_3571 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b38530ecae3735e98453e56dd7a0292.js, 20160921_a210d5e93bf8b06dbd0a1b262abe210f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46f1595f803e301ed13d99315b244aac664f908c0c0d8ab508c1d104bf7ae947"
    hash2       = "681408ae198939a760d376554e62f86e9d1fe2306266ffaee496dc9eed4d0687"

  strings:
    $s1 = "Go\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(functio" ascii
    $s2 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"I" ascii
    $s3 = "function fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){re" ascii
    $s4 = "rn \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(f" ascii
    $s5 = "),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){" ascii
    $s6 = "NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GNm\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}