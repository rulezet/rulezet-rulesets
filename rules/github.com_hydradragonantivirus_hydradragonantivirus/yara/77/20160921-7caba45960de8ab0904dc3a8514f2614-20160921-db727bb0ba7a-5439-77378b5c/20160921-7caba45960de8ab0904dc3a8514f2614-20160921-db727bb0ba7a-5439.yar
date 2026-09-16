rule _20160921_7caba45960de8ab0904dc3a8514f2614_20160921_db727bb0ba7a_5439 {
  meta:
    description = "datamaliciousorder - from files 20160921_7caba45960de8ab0904dc3a8514f2614.js, 20160921_db727bb0ba7a4addd64ea2ef7f7475f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f07b11e4aaeb00f3fa8863261ca37d382057c7775579fae2a5744dcfdb99cd95"
    hash2       = "12f83f9c7412fb362b5d1e9209d11bdf03d66f9505ff4d2247b8a85f687d4cb8"

  strings:
    $s1 = "nction fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){ret" ascii
    $s2 = "n \"XCr\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(f" ascii
    $s3 = "\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function" ascii
    $s4 = "(){return \"AUx\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\"" ascii
    $s5 = "{return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}