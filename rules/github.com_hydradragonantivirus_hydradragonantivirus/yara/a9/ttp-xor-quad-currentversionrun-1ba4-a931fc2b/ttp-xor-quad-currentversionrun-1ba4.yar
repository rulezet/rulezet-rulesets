rule TTP_XOR_QUAD_CurrentVersionRun_1ba4 {
  strings:
    $key_1ba4 = { 48 cb [2] 6c c5 [2] 47 e9 [2] 69 cb [2] 7d d0 [2] 72 ca [2] 6c d7 [2] 6e d6 [2] 75 d0 [2] 69 d7 [2] 75 f8 }

  condition:
    any of them
}