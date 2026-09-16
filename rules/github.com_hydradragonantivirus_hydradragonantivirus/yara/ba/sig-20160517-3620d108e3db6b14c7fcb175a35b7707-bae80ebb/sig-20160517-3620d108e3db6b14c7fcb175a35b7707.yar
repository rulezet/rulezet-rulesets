rule sig_20160517_3620d108e3db6b14c7fcb175a35b7707 {
  meta:
    description = "datamaliciousorder - file 20160517_3620d108e3db6b14c7fcb175a35b7707.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b92b343f61be4c5f7a488e03a43f30eb5ea4c4d4d49a5638afaa77c3c1e27893"

  strings:
    $s1 = "var auqu='viuyyeaj23mprqf2gn egnvlqtiejy1rdiobvha1o3fuyahl3ksuv3fyjjze4r4rcnwayu3n=usr1g\\'ufeyqtnsjonci12zznsx42airr4ltfwlliluo" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}