rule TTP_XOR_QUAD_CurrentVersionRun_37b7 {
  strings:
    $key_37b7 = { 64 d8 [2] 40 d6 [2] 6b fa [2] 45 d8 [2] 51 c3 [2] 5e d9 [2] 40 c4 [2] 42 c5 [2] 59 c3 [2] 45 c4 [2] 59 eb }

  condition:
    any of them
}