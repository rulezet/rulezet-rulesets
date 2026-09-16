rule _20160921_e78383c7f2f16b29dbde839d36607f19_20160921_ede755ec6df0_4076 {
  meta:
    description = "datamaliciousorder - from files 20160921_e78383c7f2f16b29dbde839d36607f19.js, 20160921_ede755ec6df0951d79fb3f792a6b28b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"
    hash2       = "24831eade0fe1d3e87c174bc2c80b113a66f4b5da6235749feba09a377913e7a"

  strings:
    $s1 = "urn \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ADy\";})()," ascii
    $s2 = "Xw\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Qh\";})(),(function " ascii
    $s3 = "})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jo\";})(),(function fuc" ascii
    $s4 = "IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Xw\";})(),(function" ascii
    $s5 = "\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"RAi\";})(),(function" ascii
    $s6 = "k(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}