rule TTP_XOR_QUAD_CurrentVersionRun_48b8 {
  strings:
    $key_48b8 = { 1b d7 [2] 3f d9 [2] 14 f5 [2] 3a d7 [2] 2e cc [2] 21 d6 [2] 3f cb [2] 3d ca [2] 26 cc [2] 3a cb [2] 26 e4 }

  condition:
    any of them
}