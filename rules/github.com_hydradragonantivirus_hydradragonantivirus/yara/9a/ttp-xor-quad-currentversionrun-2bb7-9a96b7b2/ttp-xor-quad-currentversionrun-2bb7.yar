rule TTP_XOR_QUAD_CurrentVersionRun_2bb7 {
  strings:
    $key_2bb7 = { 78 d8 [2] 5c d6 [2] 77 fa [2] 59 d8 [2] 4d c3 [2] 42 d9 [2] 5c c4 [2] 5e c5 [2] 45 c3 [2] 59 c4 [2] 45 eb }

  condition:
    any of them
}