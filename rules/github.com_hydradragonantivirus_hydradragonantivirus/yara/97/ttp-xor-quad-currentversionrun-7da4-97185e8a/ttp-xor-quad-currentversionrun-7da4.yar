rule TTP_XOR_QUAD_CurrentVersionRun_7da4 {
  strings:
    $key_7da4 = { 2e cb [2] 0a c5 [2] 21 e9 [2] 0f cb [2] 1b d0 [2] 14 ca [2] 0a d7 [2] 08 d6 [2] 13 d0 [2] 0f d7 [2] 13 f8 }

  condition:
    any of them
}