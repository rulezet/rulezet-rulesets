rule _20160921_8c8c9fad8af659443108d1078847a668_20160921_e8d738510e4d_3975 {
  meta:
    description = "datamaliciousorder - from files 20160921_8c8c9fad8af659443108d1078847a668.js, 20160921_e8d738510e4d2e0efb6c7aa18a7a58d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05c35ee4072476c50081705469d125bb2570dea942839cab58bf87874667da59"
    hash2       = "e1cd4a36522d2ad8fc8435b6cb64d8e572d8b31d4203885fa375f539a3ea7891"

  strings:
    $s1 = "urn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"To\";})(),(f" ascii
    $s2 = " fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai" ascii
    $s3 = "fuck(){return \"EHo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii
    $s4 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){" ascii
    $s5 = "k(){return \"Ai\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";" ascii
    $s6 = "tion fuck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}