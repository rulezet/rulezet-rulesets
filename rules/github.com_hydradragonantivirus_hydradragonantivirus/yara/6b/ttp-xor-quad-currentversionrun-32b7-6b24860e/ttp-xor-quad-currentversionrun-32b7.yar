rule TTP_XOR_QUAD_CurrentVersionRun_32b7 {
  strings:
    $key_32b7 = { 61 d8 [2] 45 d6 [2] 6e fa [2] 40 d8 [2] 54 c3 [2] 5b d9 [2] 45 c4 [2] 47 c5 [2] 5c c3 [2] 40 c4 [2] 5c eb }

  condition:
    any of them
}