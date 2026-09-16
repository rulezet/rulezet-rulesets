rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_afee44f6d8e7_4423 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash3       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"
    hash4       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"

  strings:
    $s1 = "return \"Oh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s2 = "{return \"To\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})" ascii
    $s3 = "turn \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(" ascii
    $s4 = "b\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function" ascii
    $s5 = "ion fuck(){return \"Ot\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}