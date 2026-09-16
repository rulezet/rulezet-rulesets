rule TTP_XOR_QUAD_CurrentVersionRun_29a6 {
  strings:
    $key_29a6 = { 7a c9 [2] 5e c7 [2] 75 eb [2] 5b c9 [2] 4f d2 [2] 40 c8 [2] 5e d5 [2] 5c d4 [2] 47 d2 [2] 5b d5 [2] 47 fa }

  condition:
    any of them
}