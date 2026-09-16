rule TTP_XOR_QUAD_CurrentVersionRun_44a4 {
  strings:
    $key_44a4 = { 17 cb [2] 33 c5 [2] 18 e9 [2] 36 cb [2] 22 d0 [2] 2d ca [2] 33 d7 [2] 31 d6 [2] 2a d0 [2] 36 d7 [2] 2a f8 }

  condition:
    any of them
}