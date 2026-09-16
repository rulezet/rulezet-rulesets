rule TTP_XOR_QUAD_CurrentVersionRun_31a5 {
  strings:
    $key_31a5 = { 62 ca [2] 46 c4 [2] 6d e8 [2] 43 ca [2] 57 d1 [2] 58 cb [2] 46 d6 [2] 44 d7 [2] 5f d1 [2] 43 d6 [2] 5f f9 }

  condition:
    any of them
}