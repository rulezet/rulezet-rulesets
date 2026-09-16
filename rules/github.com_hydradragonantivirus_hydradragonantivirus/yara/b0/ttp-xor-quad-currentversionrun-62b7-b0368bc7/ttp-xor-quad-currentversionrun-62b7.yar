rule TTP_XOR_QUAD_CurrentVersionRun_62b7 {
  strings:
    $key_62b7 = { 31 d8 [2] 15 d6 [2] 3e fa [2] 10 d8 [2] 04 c3 [2] 0b d9 [2] 15 c4 [2] 17 c5 [2] 0c c3 [2] 10 c4 [2] 0c eb }

  condition:
    any of them
}