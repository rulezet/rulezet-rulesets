rule TTP_XOR_QUAD_CurrentVersionRun_2ca6 {
  strings:
    $key_2ca6 = { 7f c9 [2] 5b c7 [2] 70 eb [2] 5e c9 [2] 4a d2 [2] 45 c8 [2] 5b d5 [2] 59 d4 [2] 42 d2 [2] 5e d5 [2] 42 fa }

  condition:
    any of them
}