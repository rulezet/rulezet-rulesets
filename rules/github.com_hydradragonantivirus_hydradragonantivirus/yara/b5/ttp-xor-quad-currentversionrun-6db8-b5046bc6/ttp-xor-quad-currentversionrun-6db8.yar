rule TTP_XOR_QUAD_CurrentVersionRun_6db8 {
  strings:
    $key_6db8 = { 3e d7 [2] 1a d9 [2] 31 f5 [2] 1f d7 [2] 0b cc [2] 04 d6 [2] 1a cb [2] 18 ca [2] 03 cc [2] 1f cb [2] 03 e4 }

  condition:
    any of them
}