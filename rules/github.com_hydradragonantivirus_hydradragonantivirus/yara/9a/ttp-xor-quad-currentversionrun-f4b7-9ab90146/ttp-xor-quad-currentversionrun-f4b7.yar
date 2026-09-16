rule TTP_XOR_QUAD_CurrentVersionRun_f4b7 {
  strings:
    $key_f4b7 = { a7 d8 [2] 83 d6 [2] a8 fa [2] 86 d8 [2] 92 c3 [2] 9d d9 [2] 83 c4 [2] 81 c5 [2] 9a c3 [2] 86 c4 [2] 9a eb }

  condition:
    any of them
}