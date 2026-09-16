rule TTP_XOR_QUAD_CurrentVersionRun_2cb7 {
  strings:
    $key_2cb7 = { 7f d8 [2] 5b d6 [2] 70 fa [2] 5e d8 [2] 4a c3 [2] 45 d9 [2] 5b c4 [2] 59 c5 [2] 42 c3 [2] 5e c4 [2] 42 eb }

  condition:
    any of them
}