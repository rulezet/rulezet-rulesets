rule _20160921_50544c5faa56c0c9ed1c35075bafc583_20160921_d82f64233994_3766 {
  meta:
    description = "datamaliciousorder - from files 20160921_50544c5faa56c0c9ed1c35075bafc583.js, 20160921_d82f642339947ac5ef4d322534d8cd70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"
    hash2       = "1af101b4afb2b8d290446a4841d803e88cb42849fb95f0cea056677487805eb6"

  strings:
    $s1 = "{return \"PDf\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Ik\";})()" ascii
    $s2 = "urn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IOs\";})(),(" ascii
    $s3 = "\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ar\";})(),(function f" ascii
    $s4 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return " ascii
    $s5 = "f\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s6 = "eturn \"GJx\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}