rule _20160921_207d0a8168d3fb16019724b9f72c41ba_20160921_4fa304d7c11d_3502 {
  meta:
    description = "datamaliciousorder - from files 20160921_207d0a8168d3fb16019724b9f72c41ba.js, 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_5e30fe0c691277f3c6d0814d796ba918.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90b56af8225bf5087b8c8ea31ab85a80e0951c3a32b8a0a0be7e09ef2efc8172"
    hash2       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash3       = "7cac2594d8c0286d3110fd3705816d41052df49790da39881cedd79b8cb5c6ed"

  strings:
    $s1 = "turn \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s2 = "uck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs" ascii
    $s3 = "nction fuck(){return \"Fv\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return" ascii
    $s4 = "uck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";" ascii
    $s5 = "\"Mw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XFd\";})(),(functi" ascii
    $s6 = ";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}