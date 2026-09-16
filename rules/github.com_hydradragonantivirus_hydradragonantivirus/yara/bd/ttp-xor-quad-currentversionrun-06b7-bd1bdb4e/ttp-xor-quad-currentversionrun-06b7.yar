rule TTP_XOR_QUAD_CurrentVersionRun_06b7 {
  strings:
    $key_06b7 = { 55 d8 [2] 71 d6 [2] 5a fa [2] 74 d8 [2] 60 c3 [2] 6f d9 [2] 71 c4 [2] 73 c5 [2] 68 c3 [2] 74 c4 [2] 68 eb }

  condition:
    any of them
}