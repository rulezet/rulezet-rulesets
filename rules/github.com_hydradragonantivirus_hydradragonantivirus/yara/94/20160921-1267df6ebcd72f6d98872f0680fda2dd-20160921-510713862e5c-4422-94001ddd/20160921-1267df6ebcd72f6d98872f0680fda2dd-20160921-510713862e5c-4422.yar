rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_510713862e5c_4422 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_510713862e5c8c05841e5272407127f3.js, 20160921_a160e4a385807ffcdde4f99a0c57b6b2.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "9f9cd81d24cdba49fd83fed4aa0c3ce028729b44e223720bae200336b5992e5e"
    hash3       = "c3eeb2af6e453aec7ede2bba435e7dcf60f7497a94584d1908a2235d79c28a34"
    hash4       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash5       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"

  strings:
    $s1 = "){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";}" ascii
    $s2 = "IKv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(functio" ascii
    $s3 = "on fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii
    $s4 = "ction fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s5 = "rn \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}