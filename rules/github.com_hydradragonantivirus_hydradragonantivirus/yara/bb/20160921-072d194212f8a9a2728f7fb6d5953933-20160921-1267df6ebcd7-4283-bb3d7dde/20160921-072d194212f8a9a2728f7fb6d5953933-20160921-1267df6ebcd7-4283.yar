rule _20160921_072d194212f8a9a2728f7fb6d5953933_20160921_1267df6ebcd7_4283 {
  meta:
    description = "datamaliciousorder - from files 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js, 20160921_c07f026b9458324f489ec08b7859e758.js, 20160921_e6771cfa257410eb61913de76cb777a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash2       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash3       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"
    hash4       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash5       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"
    hash6       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"
    hash7       = "009074e75815902f1e36daa21c179598b761767cd8d92eb363f3541838abdbfe"

  strings:
    $s1 = "urn \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s2 = "Rn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(functio" ascii
    $s3 = "eturn \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Jo\";})()," ascii
    $s4 = "n fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"" ascii
    $s5 = " fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UO" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}