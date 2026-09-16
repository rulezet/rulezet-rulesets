rule TTP_XOR_QUAD_CurrentVersionRun_28b8 {
  strings:
    $key_28b8 = { 7b d7 [2] 5f d9 [2] 74 f5 [2] 5a d7 [2] 4e cc [2] 41 d6 [2] 5f cb [2] 5d ca [2] 46 cc [2] 5a cb [2] 46 e4 }

  condition:
    any of them
}