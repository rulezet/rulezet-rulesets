rule TTP_XOR_QUAD_CurrentVersionRun_76b7 {
  strings:
    $key_76b7 = { 25 d8 [2] 01 d6 [2] 2a fa [2] 04 d8 [2] 10 c3 [2] 1f d9 [2] 01 c4 [2] 03 c5 [2] 18 c3 [2] 04 c4 [2] 18 eb }

  condition:
    any of them
}