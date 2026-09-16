rule TTP_XOR_QUAD_CurrentVersionRun_20a6 {
  strings:
    $key_20a6 = { 73 c9 [2] 57 c7 [2] 7c eb [2] 52 c9 [2] 46 d2 [2] 49 c8 [2] 57 d5 [2] 55 d4 [2] 4e d2 [2] 52 d5 [2] 4e fa }

  condition:
    any of them
}