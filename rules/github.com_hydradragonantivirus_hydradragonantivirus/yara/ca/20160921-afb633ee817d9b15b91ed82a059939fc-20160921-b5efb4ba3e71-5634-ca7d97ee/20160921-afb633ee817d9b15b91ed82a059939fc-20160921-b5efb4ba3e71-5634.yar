rule _20160921_afb633ee817d9b15b91ed82a059939fc_20160921_b5efb4ba3e71_5634 {
  meta:
    description = "datamaliciousorder - from files 20160921_afb633ee817d9b15b91ed82a059939fc.js, 20160921_b5efb4ba3e712545d64a2d00b3dcd76e.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a4e330bd3ec71aa3dc8fd3d5b2fa656b04d49cb5ee4e5478a50a6336c5bf9e5"
    hash2       = "ff8ef85b589636068d365f9ee4a0b9c7119baeb269d0a34c9810fca4b3faf1cf"
    hash3       = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1 = "tion fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s2 = "urn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(" ascii
    $s3 = "){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";}" ascii
    $s4 = "n \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(func" ascii
    $s5 = "nction fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}