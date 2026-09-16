rule _20160921_4fa304d7c11deb5fb9cd6514d5a983de_20160921_8dce9d2aa0d1_3764 {
  meta:
    description = "datamaliciousorder - from files 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash2       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"

  strings:
    $s1 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"" ascii
    $s2 = "GWo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(funct" ascii
    $s3 = "ck(){return \"Py\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu" ascii
    $s4 = "o\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function" ascii
    $s5 = "eturn \"Qh\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s6 = "nction fuck(){return \"Ot\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}