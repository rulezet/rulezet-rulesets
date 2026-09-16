rule _20160921_3b7ec37cdbfac434e32c8743c60228af_20160921_d0ae6acc5cc4_2901 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b7ec37cdbfac434e32c8743c60228af.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86390741cf6e610c2e526db749631548b514c268decade5a5870edfebb141d4b"
    hash2       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"

  strings:
    $s1 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"YQt\";})(),(function fuc" ascii
    $s2 = "n fuck(){return \"Qh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"M" ascii
    $s3 = "ion fuck(){return \"Sx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s4 = "tion fuck(){return \"XCr\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retur" ascii
    $s5 = ";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function f" ascii
    $s6 = "return \"TTs\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})" ascii
    $s7 = "return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XFd\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}