rule TTP_XOR_QUAD_CurrentVersionRun_5aa4 {
  strings:
    $key_5aa4 = { 09 cb [2] 2d c5 [2] 06 e9 [2] 28 cb [2] 3c d0 [2] 33 ca [2] 2d d7 [2] 2f d6 [2] 34 d0 [2] 28 d7 [2] 34 f8 }

  condition:
    any of them
}