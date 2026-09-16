rule _20160921_c694815b18c140f34c0f79f86106d901_20160921_e07d4e2b8017_3142 {
  meta:
    description = "datamaliciousorder - from files 20160921_c694815b18c140f34c0f79f86106d901.js, 20160921_e07d4e2b80172d933515ba35e18c07eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "650c20b763cdd9e1631c1f76f67b04a911cfce7996c1e9928b9c3b7fe1f8e7e5"
    hash2       = "d93efcba4ba3ef570f21adda2cc5413ab9ed3865a53a97ad1e05113ebc7c4787"

  strings:
    $s1 = "Pu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xg\";})(),(function " ascii
    $s2 = " \"We\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s3 = "){return \"Zy\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})" ascii
    $s4 = ")(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(" ascii
    $s5 = "{return \"Wo0\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";}" ascii
    $s6 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return " ascii
    $s7 = "urn \"Xw\";})(),(function fuck(){return \"Az\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}