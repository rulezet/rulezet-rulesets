rule TTP_XOR_QUAD_CurrentVersionRun_04a6 {
  strings:
    $key_04a6 = { 57 c9 [2] 73 c7 [2] 58 eb [2] 76 c9 [2] 62 d2 [2] 6d c8 [2] 73 d5 [2] 71 d4 [2] 6a d2 [2] 76 d5 [2] 6a fa }

  condition:
    any of them
}