rule _20160921_2a4687842acdb7843675f91c11ae7986_20160921_5a42eec12fd0_1686 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4687842acdb7843675f91c11ae7986.js, 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js, 20160921_f69cc523f43841dbc6246209e09d2b8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b483b885082d284a148ab2a97b57881cd387b85b477025ad126d680e158bc62"
    hash2       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash3       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"
    hash4       = "82ee8104aecfd309a85de470b641e14f7ef67f3b3ec968ce41eade759620fd53"

  strings:
    $s1  = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jh\";})(),(func" ascii
    $s2  = "urn \"Wo0\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s3  = ";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"RAi\";})(),(function fu" ascii
    $s4  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Py\";})(),(function fuck(){retur" ascii
    $s5  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return" ascii
    $s6  = "FJs\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xw\";})(),(function" ascii
    $s7  = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"EHo\";})(),(function fuck(" ascii
    $s8  = "ck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu" ascii
    $s9  = "k(){return \"Nm\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";}" ascii
    $s10 = "rn \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(f" ascii
    $s11 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ot\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}