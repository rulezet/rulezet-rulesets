rule TTP_XOR_QUAD_CurrentVersionRun_e4b7 {
  strings:
    $key_e4b7 = { b7 d8 [2] 93 d6 [2] b8 fa [2] 96 d8 [2] 82 c3 [2] 8d d9 [2] 93 c4 [2] 91 c5 [2] 8a c3 [2] 96 c4 [2] 8a eb }

  condition:
    any of them
}