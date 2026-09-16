rule _20160921_be8454f98b5a24b3ec56590bd13ee274_20160921_d88b1be24c58_1521 {
  meta:
    description = "datamaliciousorder - from files 20160921_be8454f98b5a24b3ec56590bd13ee274.js, 20160921_d88b1be24c583b3513de141e173a825f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"
    hash2       = "be789e0d16008ea27a540870c4b670071885fb31e3c8c6ebfb775def3b30a551"

  strings:
    $s1  = " fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Y" ascii
    $s2  = "fuck(){return \"SUi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"N" ascii
    $s3  = "\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Sx\";})(),(function f" ascii
    $s4  = "ction fuck(){return \"OQr\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){retur" ascii
    $s5  = "on fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"" ascii
    $s6  = "(function fuck(){return \"ZLd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){" ascii
    $s7  = "n \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(f" ascii
    $s8  = "),(function fuck(){return \"MIl\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(" ascii
    $s9  = "{return \"Oh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(" ascii
    $s10 = "return \"USf\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})" ascii
    $s11 = "return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})" ascii
    $s12 = "urn \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"ADy\";})(),(" ascii
    $s13 = "eturn \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Mw\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}