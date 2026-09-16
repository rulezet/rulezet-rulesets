rule _20160921_70d636d209e6f109a21746567376cc81_20160921_afb633ee817d_2502 {
  meta:
    description = "datamaliciousorder - from files 20160921_70d636d209e6f109a21746567376cc81.js, 20160921_afb633ee817d9b15b91ed82a059939fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e26044e7a07a5a675f3b388e6309b138b9e7a1aa61556485f444025164a158e"
    hash2       = "7a4e330bd3ec71aa3dc8fd3d5b2fa656b04d49cb5ee4e5478a50a6336c5bf9e5"

  strings:
    $s1 = " fuck(){return \"ZLd\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s2 = ",(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){r" ascii
    $s3 = "Xw\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"LLv\";})(),(functio" ascii
    $s4 = "{return \"Av\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})()" ascii
    $s5 = ",(function fuck(){return \"YQt\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){" ascii
    $s6 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return " ascii
    $s7 = "g\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xw\";})(),(function" ascii
    $s8 = "k(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Np\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}