rule TTP_XOR_QUAD_CurrentVersionRun_7db8 {
  strings:
    $key_7db8 = { 2e d7 [2] 0a d9 [2] 21 f5 [2] 0f d7 [2] 1b cc [2] 14 d6 [2] 0a cb [2] 08 ca [2] 13 cc [2] 0f cb [2] 13 e4 }

  condition:
    any of them
}