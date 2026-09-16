rule _20160921_3b2083afdb57ae7e611f6f42c6787c73_20160921_766f6fcbd2a9_4981 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b2083afdb57ae7e611f6f42c6787c73.js, 20160921_766f6fcbd2a94a55747a3f5b9a204b0e.js, 20160921_885a9e110f52f3ca103e4718673adb3b.js, 20160921_9ab244a7866dc1a3d98006482dd7da38.js, 20160921_e2cf0a7330632dcfdd75ef1c324289b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c81783a1510b3172e1702365554b0e2000709a4e4217a8970aa381c9b357e36"
    hash2       = "7ac34bd929ce60a874936fef08adcce78783c70441a9eff1cd392604bcf45ff7"
    hash3       = "a777a2e324ff6d64746b42793d888cea6f2beec30ded4165b5b13eda473e58bf"
    hash4       = "99692f93901b579e0992cf6f44c274569bb1257cf12f2eebf5baceb7cb31d6af"
    hash5       = "ad7238fc2ad12cca7ecf6bccdbe5df095519b23408e1a1f63f4ad19a50469d2e"

  strings:
    $s1 = "nction fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retu" ascii
    $s2 = "\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function" ascii
    $s3 = "(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";" ascii
    $s4 = "tion fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){retur" ascii
    $s5 = "{return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}