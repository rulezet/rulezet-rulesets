rule TTP_XOR_QUAD_CurrentVersionRun_72b7 {
  strings:
    $key_72b7 = { 21 d8 [2] 05 d6 [2] 2e fa [2] 00 d8 [2] 14 c3 [2] 1b d9 [2] 05 c4 [2] 07 c5 [2] 1c c3 [2] 00 c4 [2] 1c eb }

  condition:
    any of them
}