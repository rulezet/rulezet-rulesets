rule TTP_XOR_QUAD_CurrentVersionRun_44a6 {
  strings:
    $key_44a6 = { 17 c9 [2] 33 c7 [2] 18 eb [2] 36 c9 [2] 22 d2 [2] 2d c8 [2] 33 d5 [2] 31 d4 [2] 2a d2 [2] 36 d5 [2] 2a fa }

  condition:
    any of them
}