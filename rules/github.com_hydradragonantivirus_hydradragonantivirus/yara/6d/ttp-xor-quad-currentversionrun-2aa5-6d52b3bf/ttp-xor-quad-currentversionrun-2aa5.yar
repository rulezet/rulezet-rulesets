rule TTP_XOR_QUAD_CurrentVersionRun_2aa5 {
  strings:
    $key_2aa5 = { 79 ca [2] 5d c4 [2] 76 e8 [2] 58 ca [2] 4c d1 [2] 43 cb [2] 5d d6 [2] 5f d7 [2] 44 d1 [2] 58 d6 [2] 44 f9 }

  condition:
    any of them
}