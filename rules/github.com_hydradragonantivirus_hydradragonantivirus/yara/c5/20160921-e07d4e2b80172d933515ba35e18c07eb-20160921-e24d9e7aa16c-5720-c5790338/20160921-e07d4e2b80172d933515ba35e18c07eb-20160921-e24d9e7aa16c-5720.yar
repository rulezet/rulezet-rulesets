rule _20160921_e07d4e2b80172d933515ba35e18c07eb_20160921_e24d9e7aa16c_5720 {
  meta:
    description = "datamaliciousorder - from files 20160921_e07d4e2b80172d933515ba35e18c07eb.js, 20160921_e24d9e7aa16c031b748aba6965b02dcb.js, 20160921_e71c0801261b54c695ea1dac03e838bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d93efcba4ba3ef570f21adda2cc5413ab9ed3865a53a97ad1e05113ebc7c4787"
    hash2       = "c005836c702d4e1615fb302fc6f799ca097db41daa5b8cf6a66e8874a454d65b"
    hash3       = "c36b557af1bcfc43e39bfaabcd74048c39fc37b5ac0e9561b161a6d3d2e54e76"

  strings:
    $s1 = "fuck(){return \"Vf\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Py\"" ascii
    $s2 = ",(function fuck(){return \"Cd\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s3 = "{return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s4 = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Za\";})(),(funct" ascii
    $s5 = "n \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Dc\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}