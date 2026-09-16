rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_aab5fb25ea89_4432 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_aab5fb25ea8971982ac223655d50aba2.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"
    hash3       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash4       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"

  strings:
    $s1 = "CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"GNm\";})(),(funct" ascii
    $s2 = "turn \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"YAv\";})()," ascii
    $s3 = "return \"Nm\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s4 = "){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Yk\";})(" ascii
    $s5 = "ion fuck(){return \"Wo0\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}