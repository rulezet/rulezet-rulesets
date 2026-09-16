rule _20160921_063094039ef79437a260d3dde960797a_20160921_dc73cfa7a33e_3249 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"

  strings:
    $s1 = "ction fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return" ascii
    $s2 = "UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"XFd\";})(),(funct" ascii
    $s3 = "(function fuck(){return \"OQr\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){re" ascii
    $s4 = ";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(function fuc" ascii
    $s5 = "{return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"NKq\";})(" ascii
    $s6 = "turn \"Av\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"FJs\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}