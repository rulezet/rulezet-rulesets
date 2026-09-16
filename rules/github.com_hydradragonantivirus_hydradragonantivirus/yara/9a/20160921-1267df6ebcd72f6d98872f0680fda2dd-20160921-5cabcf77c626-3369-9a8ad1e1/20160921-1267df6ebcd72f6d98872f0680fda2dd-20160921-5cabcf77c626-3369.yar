rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_5cabcf77c626_3369 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_5cabcf77c626e288d5cbd9104a914ae8.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "9493e4251106014081e4b141c6296c51b00c9ba7a799bcb978ea6226cd127d34"
    hash3       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash4       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"

  strings:
    $s1 = "n fuck(){return \"Hs\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s2 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){ret" ascii
    $s3 = "ction fuck(){return \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retu" ascii
    $s4 = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\";})()" ascii
    $s5 = "ck(){return \"Vb\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Py\"" ascii
    $s6 = "\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}