rule _20160921_6a795b29889480550a8440815b06fa7d_20160921_85f2776f4fe6_2105 {
  meta:
    description = "datamaliciousorder - from files 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_85f2776f4fe640d2373f51ddbc697659.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash2       = "0604503e68d6aa73ca3bbdb29b958ea47ad4c81b2f77ad9db2b0e8467b1c870d"

  strings:
    $s1 = "ck(){return \"GJx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\"" ascii
    $s2 = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ai" ascii
    $s3 = "(function fuck(){return \"SUi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s4 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){retu" ascii
    $s5 = "n fuck(){return \"Py\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"R" ascii
    $s6 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"" ascii
    $s7 = "(function fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){r" ascii
    $s8 = "Xf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ug\";})(),(function" ascii
    $s9 = "{return \"ZWu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Np\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}