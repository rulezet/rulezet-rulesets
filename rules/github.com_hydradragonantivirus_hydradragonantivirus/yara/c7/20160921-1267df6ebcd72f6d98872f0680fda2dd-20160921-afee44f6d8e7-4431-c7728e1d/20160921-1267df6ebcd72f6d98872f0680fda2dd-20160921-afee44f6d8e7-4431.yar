rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_afee44f6d8e7_4431 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js, 20160921_b1a0d856c15e8cb36e6ba699332db942.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash3       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"
    hash4       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"

  strings:
    $s1 = " \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(func" ascii
    $s2 = "})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii
    $s3 = "ADy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s4 = "){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s5 = "urn \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}