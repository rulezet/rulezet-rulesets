rule TTP_XOR_QUAD_CurrentVersionRun_7aa4 {
  strings:
    $key_7aa4 = { 29 cb [2] 0d c5 [2] 26 e9 [2] 08 cb [2] 1c d0 [2] 13 ca [2] 0d d7 [2] 0f d6 [2] 14 d0 [2] 08 d7 [2] 14 f8 }

  condition:
    any of them
}