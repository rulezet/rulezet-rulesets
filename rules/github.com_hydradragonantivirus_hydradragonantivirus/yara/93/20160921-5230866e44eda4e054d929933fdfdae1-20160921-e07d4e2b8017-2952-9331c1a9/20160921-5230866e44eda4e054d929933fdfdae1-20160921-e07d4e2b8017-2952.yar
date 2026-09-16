rule _20160921_5230866e44eda4e054d929933fdfdae1_20160921_e07d4e2b8017_2952 {
  meta:
    description = "datamaliciousorder - from files 20160921_5230866e44eda4e054d929933fdfdae1.js, 20160921_e07d4e2b80172d933515ba35e18c07eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b11d10d6c2a935fa29f47c13ee54d426aac8d667f3bc2f79681ac7e4d365c76"
    hash2       = "d93efcba4ba3ef570f21adda2cc5413ab9ed3865a53a97ad1e05113ebc7c4787"

  strings:
    $s1 = "turn \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"NKq\";})(),(" ascii
    $s2 = "(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(function fuck()" ascii
    $s3 = "uck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IP" ascii
    $s4 = "n \"Av\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"FJs\";})(),(fun" ascii
    $s5 = "nction fuck(){return \"MUs\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){retur" ascii
    $s6 = "on fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"" ascii
    $s7 = "\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UXf\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}