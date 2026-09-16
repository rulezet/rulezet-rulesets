rule _20160921_063094039ef79437a260d3dde960797a_20160921_70b567ca258b_4250 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_70b567ca258b3c505e14f3c712366f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"

  strings:
    $s1 = ";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fu" ascii
    $s2 = "eturn \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZWu\";})()" ascii
    $s3 = "{return \"Nm\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Hs\";})()" ascii
    $s4 = "rn \"YAv\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})(),(" ascii
    $s5 = "on fuck(){return \"Et\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}