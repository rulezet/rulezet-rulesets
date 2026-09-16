rule TTP_XOR_QUAD_CurrentVersionRun_73b8 {
  strings:
    $key_73b8 = { 20 d7 [2] 04 d9 [2] 2f f5 [2] 01 d7 [2] 15 cc [2] 1a d6 [2] 04 cb [2] 06 ca [2] 1d cc [2] 01 cb [2] 1d e4 }

  condition:
    any of them
}