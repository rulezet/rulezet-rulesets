rule TTP_XOR_QUAD_CurrentVersionRun_0ba5 {
  strings:
    $key_0ba5 = { 58 ca [2] 7c c4 [2] 57 e8 [2] 79 ca [2] 6d d1 [2] 62 cb [2] 7c d6 [2] 7e d7 [2] 65 d1 [2] 79 d6 [2] 65 f9 }

  condition:
    any of them
}