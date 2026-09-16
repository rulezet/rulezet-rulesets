rule _20160921_5775da34d70f97a2d7aa3296f909af35_20160921_d1c97b87a698_5222 {
  meta:
    description = "datamaliciousorder - from files 20160921_5775da34d70f97a2d7aa3296f909af35.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1 = "rn \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(fu" ascii
    $s2 = "\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function f" ascii
    $s3 = "v\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"RPt\";})(),(functio" ascii
    $s4 = "\"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(functi" ascii
    $s5 = "on f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}