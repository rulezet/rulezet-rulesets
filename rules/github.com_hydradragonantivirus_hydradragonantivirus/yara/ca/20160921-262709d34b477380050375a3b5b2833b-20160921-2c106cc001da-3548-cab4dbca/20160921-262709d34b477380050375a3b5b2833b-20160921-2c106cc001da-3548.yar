rule _20160921_262709d34b477380050375a3b5b2833b_20160921_2c106cc001da_3548 {
  meta:
    description = "datamaliciousorder - from files 20160921_262709d34b477380050375a3b5b2833b.js, 20160921_2c106cc001daa2dffdfde7e2aa5c908b.js, 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2738de24af2af834f5ce43b4e99137d47cd1993ec0b6dc3c1071deb99efcd62c"
    hash2       = "ca5356b92abf859d45d843749f45e5e06c7d045b4e7ea5d215ab87cdb8c8f66b"
    hash3       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"

  strings:
    $s1 = "UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s2 = "(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck()" ascii
    $s3 = "){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})" ascii
    $s4 = "\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fu" ascii
    $s5 = "n \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(fu" ascii
    $s6 = "MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}