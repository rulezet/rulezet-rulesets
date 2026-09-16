rule TTP_XOR_QUAD_CurrentVersionRun_41a4 {
  strings:
    $key_41a4 = { 12 cb [2] 36 c5 [2] 1d e9 [2] 33 cb [2] 27 d0 [2] 28 ca [2] 36 d7 [2] 34 d6 [2] 2f d0 [2] 33 d7 [2] 2f f8 }

  condition:
    any of them
}