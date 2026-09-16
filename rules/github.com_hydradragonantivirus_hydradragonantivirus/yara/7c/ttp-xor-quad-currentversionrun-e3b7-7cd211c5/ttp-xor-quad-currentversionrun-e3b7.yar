rule TTP_XOR_QUAD_CurrentVersionRun_e3b7 {
  strings:
    $key_e3b7 = { b0 d8 [2] 94 d6 [2] bf fa [2] 91 d8 [2] 85 c3 [2] 8a d9 [2] 94 c4 [2] 96 c5 [2] 8d c3 [2] 91 c4 [2] 8d eb }

  condition:
    any of them
}