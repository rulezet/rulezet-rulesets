rule _20160921_01da6b0c1b5614c5877e0dd7b6be4036_20160921_1267df6ebcd7_4126 {
  meta:
    description = "datamaliciousorder - from files 20160921_01da6b0c1b5614c5877e0dd7b6be4036.js, 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_17642c69cbfb276056f3695ae22dad4c.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5da941f7d098e0926acf7ad9efedc9f91495115fc83f288580eba79e44574693"
    hash2       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash3       = "4cdbf9fba4e3fec424cf182fd21fa3c400b0649ca09f140375a47df12248955c"
    hash4       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash5       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"

  strings:
    $s1 = "uck(){return \"OQr\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe" ascii
    $s2 = " \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(fun" ascii
    $s3 = "turn \"Ar\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s4 = "ck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs" ascii
    $s5 = "),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}