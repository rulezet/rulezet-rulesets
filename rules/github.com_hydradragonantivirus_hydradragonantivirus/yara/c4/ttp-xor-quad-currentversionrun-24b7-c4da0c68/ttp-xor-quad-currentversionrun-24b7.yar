rule TTP_XOR_QUAD_CurrentVersionRun_24b7 {
  strings:
    $key_24b7 = { 77 d8 [2] 53 d6 [2] 78 fa [2] 56 d8 [2] 42 c3 [2] 4d d9 [2] 53 c4 [2] 51 c5 [2] 4a c3 [2] 56 c4 [2] 4a eb }

  condition:
    any of them
}