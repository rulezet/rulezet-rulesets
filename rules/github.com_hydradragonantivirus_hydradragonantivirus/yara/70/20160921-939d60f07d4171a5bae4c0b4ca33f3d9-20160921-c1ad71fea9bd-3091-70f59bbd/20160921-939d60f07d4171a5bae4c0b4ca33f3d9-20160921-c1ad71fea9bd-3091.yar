rule _20160921_939d60f07d4171a5bae4c0b4ca33f3d9_20160921_c1ad71fea9bd_3091 {
  meta:
    description = "datamaliciousorder - from files 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js, 20160921_c1ad71fea9bd3e371590c0c373f087a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"
    hash2       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"

  strings:
    $s1 = "n \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Vj\";})(),(func" ascii
    $s2 = "tion f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s3 = "urn \"PTi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s4 = "Ux\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function" ascii
    $s5 = "Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s6 = "f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\"" ascii
    $s7 = "rn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}