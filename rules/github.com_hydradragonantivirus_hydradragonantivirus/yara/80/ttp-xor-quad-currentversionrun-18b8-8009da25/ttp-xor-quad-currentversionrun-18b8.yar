rule TTP_XOR_QUAD_CurrentVersionRun_18b8 {
  strings:
    $key_18b8 = { 4b d7 [2] 6f d9 [2] 44 f5 [2] 6a d7 [2] 7e cc [2] 71 d6 [2] 6f cb [2] 6d ca [2] 76 cc [2] 6a cb [2] 76 e4 }

  condition:
    any of them
}