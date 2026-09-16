rule TTP_XOR_QUAD_CurrentVersionRun_4db8 {
  strings:
    $key_4db8 = { 1e d7 [2] 3a d9 [2] 11 f5 [2] 3f d7 [2] 2b cc [2] 24 d6 [2] 3a cb [2] 38 ca [2] 23 cc [2] 3f cb [2] 23 e4 }

  condition:
    any of them
}