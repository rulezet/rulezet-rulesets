rule TTP_XOR_QUAD_CurrentVersionRun_3ba4 {
  strings:
    $key_3ba4 = { 68 cb [2] 4c c5 [2] 67 e9 [2] 49 cb [2] 5d d0 [2] 52 ca [2] 4c d7 [2] 4e d6 [2] 55 d0 [2] 49 d7 [2] 55 f8 }

  condition:
    any of them
}