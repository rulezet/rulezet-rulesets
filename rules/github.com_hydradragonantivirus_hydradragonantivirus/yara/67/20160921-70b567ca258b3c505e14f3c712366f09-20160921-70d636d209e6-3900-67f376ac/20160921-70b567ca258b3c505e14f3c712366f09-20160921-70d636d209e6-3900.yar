rule _20160921_70b567ca258b3c505e14f3c712366f09_20160921_70d636d209e6_3900 {
  meta:
    description = "datamaliciousorder - from files 20160921_70b567ca258b3c505e14f3c712366f09.js, 20160921_70d636d209e6f109a21746567376cc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"
    hash2       = "6e26044e7a07a5a675f3b388e6309b138b9e7a1aa61556485f444025164a158e"

  strings:
    $s1 = "(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"To\";}" ascii
    $s2 = ",(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){r" ascii
    $s3 = "\"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"PDf\";})(),(func" ascii
    $s4 = "ion fuck(){return \"Qh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return " ascii
    $s5 = "n fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"" ascii
    $s6 = "k(){return \"Ar\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}