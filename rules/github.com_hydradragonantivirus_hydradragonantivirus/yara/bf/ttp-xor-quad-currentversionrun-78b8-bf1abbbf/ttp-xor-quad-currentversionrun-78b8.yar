rule TTP_XOR_QUAD_CurrentVersionRun_78b8 {
  strings:
    $key_78b8 = { 2b d7 [2] 0f d9 [2] 24 f5 [2] 0a d7 [2] 1e cc [2] 11 d6 [2] 0f cb [2] 0d ca [2] 16 cc [2] 0a cb [2] 16 e4 }

  condition:
    any of them
}