rule TTP_XOR_QUAD_CurrentVersionRun_0da4 {
  strings:
    $key_0da4 = { 5e cb [2] 7a c5 [2] 51 e9 [2] 7f cb [2] 6b d0 [2] 64 ca [2] 7a d7 [2] 78 d6 [2] 63 d0 [2] 7f d7 [2] 63 f8 }

  condition:
    any of them
}