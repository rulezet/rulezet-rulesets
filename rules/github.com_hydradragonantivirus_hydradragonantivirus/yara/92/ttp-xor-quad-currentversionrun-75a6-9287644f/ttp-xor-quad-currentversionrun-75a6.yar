rule TTP_XOR_QUAD_CurrentVersionRun_75a6 {
  strings:
    $key_75a6 = { 26 c9 [2] 02 c7 [2] 29 eb [2] 07 c9 [2] 13 d2 [2] 1c c8 [2] 02 d5 [2] 00 d4 [2] 1b d2 [2] 07 d5 [2] 1b fa }

  condition:
    any of them
}