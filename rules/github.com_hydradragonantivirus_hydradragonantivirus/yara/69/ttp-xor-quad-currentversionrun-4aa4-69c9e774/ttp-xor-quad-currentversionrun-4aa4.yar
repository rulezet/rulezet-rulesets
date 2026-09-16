rule TTP_XOR_QUAD_CurrentVersionRun_4aa4 {
  strings:
    $key_4aa4 = { 19 cb [2] 3d c5 [2] 16 e9 [2] 38 cb [2] 2c d0 [2] 23 ca [2] 3d d7 [2] 3f d6 [2] 24 d0 [2] 38 d7 [2] 24 f8 }

  condition:
    any of them
}