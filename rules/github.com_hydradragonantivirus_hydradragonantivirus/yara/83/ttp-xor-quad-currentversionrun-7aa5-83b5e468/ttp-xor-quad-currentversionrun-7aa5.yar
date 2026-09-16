rule TTP_XOR_QUAD_CurrentVersionRun_7aa5 {
  strings:
    $key_7aa5 = { 29 ca [2] 0d c4 [2] 26 e8 [2] 08 ca [2] 1c d1 [2] 13 cb [2] 0d d6 [2] 0f d7 [2] 14 d1 [2] 08 d6 [2] 14 f9 }

  condition:
    any of them
}