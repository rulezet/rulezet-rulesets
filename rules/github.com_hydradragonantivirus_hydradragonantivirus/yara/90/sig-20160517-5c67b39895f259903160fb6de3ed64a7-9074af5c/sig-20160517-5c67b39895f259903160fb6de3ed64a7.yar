rule sig_20160517_5c67b39895f259903160fb6de3ed64a7 {
  meta:
    description = "datamaliciousorder - file 20160517_5c67b39895f259903160fb6de3ed64a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2db1b6ee97f942d628e1bbb0beb21ccad56c6d6b89a395b6690051c9dab986d5"

  strings:
    $s1 = "var tjvcsn='vc4i1fauko24rmczvs sx4l2qgdlgtth3ha2xmhaqifatx4vvuw2zs2sjqxzjapcdzydk3ioalq1eg3ztagw=ngt1g\\'uuucstjxh1bcg1pjjnmn4ew" ascii
    $s2 = "\"+\"cript\"+\".RegE\"+\"xp\");   ddoiq2mux3=r4+\"v\"+\"al\";   WScript.lister=5;   ddoiq2mux3=\"\"+\"s\";   ww=232323;   }catch" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}