rule _20160921_b7400937fc4eb76c7ea3adaa321d7619_20160921_d1c97b87a698_5652 {
  meta:
    description = "datamaliciousorder - from files 20160921_b7400937fc4eb76c7ea3adaa321d7619.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91a8cd111f3381e8f00611988dc7860cfb507d4d297884f9d7d7a01ae96c0fca"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1 = "000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Vj" ascii
    $s2 = "){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";}" ascii
    $s3 = "unction f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){ret" ascii
    $s4 = " f000(){return \"PTi\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"G" ascii
    $s5 = ",(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}