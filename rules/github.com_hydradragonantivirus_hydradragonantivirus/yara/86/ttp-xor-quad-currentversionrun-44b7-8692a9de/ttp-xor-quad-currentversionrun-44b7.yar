rule TTP_XOR_QUAD_CurrentVersionRun_44b7 {
  strings:
    $key_44b7 = { 17 d8 [2] 33 d6 [2] 18 fa [2] 36 d8 [2] 22 c3 [2] 2d d9 [2] 33 c4 [2] 31 c5 [2] 2a c3 [2] 36 c4 [2] 2a eb }

  condition:
    any of them
}