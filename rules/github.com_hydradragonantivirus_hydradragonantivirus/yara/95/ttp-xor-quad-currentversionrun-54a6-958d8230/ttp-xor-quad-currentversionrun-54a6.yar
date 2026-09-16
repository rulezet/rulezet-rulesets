rule TTP_XOR_QUAD_CurrentVersionRun_54a6 {
  strings:
    $key_54a6 = { 07 c9 [2] 23 c7 [2] 08 eb [2] 26 c9 [2] 32 d2 [2] 3d c8 [2] 23 d5 [2] 21 d4 [2] 3a d2 [2] 26 d5 [2] 3a fa }

  condition:
    any of them
}