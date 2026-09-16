rule _20160921_4cda342a49d7c489fce63509619cc08e_20160921_5f040a1454ca_1858 {
  meta:
    description = "datamaliciousorder - from files 20160921_4cda342a49d7c489fce63509619cc08e.js, 20160921_5f040a1454cafc62100cb4449da0b7e2.js, 20160921_5fbbbcb8f403a68df153b90d52e5fff9.js, 20160921_88a4a74b87ab9fd3fb3dd307f9d7213d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cabf2bed3c4b1c46c86905c48d0ce38dc15e155546fd36ce4d681314485c6aeb"
    hash2       = "0ffb0f3f8e3e8ace2b8b6c1bccf53c8b5a11fd2ed00ff3b54971e8b0ca5e139d"
    hash3       = "1e2661f95b6bb745bac719b1313cfa9a489ecd857f66bfe9fe5398391e372ca4"
    hash4       = "33ff531b193580829a3217137df52750b8df810994123bd1d02bfced3fa6c2ce"

  strings:
    $s1  = ";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s2  = "n fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s3  = "tion fuck(){return \"DWe\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s4  = " \"Ot\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s5  = "u\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Py\";})(),(function " ascii
    $s6  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s7  = "ion fuck(){return \"MIl\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return " ascii
    $s8  = "fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu" ascii
    $s9  = "k(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Fv\";}" ascii
    $s10 = "n fuck(){return \"Ot\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IP" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}