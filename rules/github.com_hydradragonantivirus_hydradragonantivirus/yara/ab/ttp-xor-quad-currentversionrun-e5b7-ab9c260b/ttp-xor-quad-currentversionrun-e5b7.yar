rule TTP_XOR_QUAD_CurrentVersionRun_e5b7 {
  strings:
    $key_e5b7 = { b6 d8 [2] 92 d6 [2] b9 fa [2] 97 d8 [2] 83 c3 [2] 8c d9 [2] 92 c4 [2] 90 c5 [2] 8b c3 [2] 97 c4 [2] 8b eb }

  condition:
    any of them
}