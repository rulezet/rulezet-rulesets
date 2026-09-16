rule _20160921_e072f9d237d6a3b969fa334b2e277a33_20160921_e8d738510e4d_4072 {
  meta:
    description = "datamaliciousorder - from files 20160921_e072f9d237d6a3b969fa334b2e277a33.js, 20160921_e8d738510e4d2e0efb6c7aa18a7a58d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a03793a4e6175c2a80395cdedba1eaf5878722aa36c4cbfae104768ed79890d"
    hash2       = "e1cd4a36522d2ad8fc8435b6cb64d8e572d8b31d4203885fa375f539a3ea7891"

  strings:
    $s1 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc" ascii
    $s2 = "on fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s3 = "urn \"SUi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s4 = "k(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\"" ascii
    $s5 = "urn \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s6 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Sx\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}