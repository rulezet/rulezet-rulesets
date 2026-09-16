rule TTP_XOR_QUAD_CurrentVersionRun_10a6 {
  strings:
    $key_10a6 = { 43 c9 [2] 67 c7 [2] 4c eb [2] 62 c9 [2] 76 d2 [2] 79 c8 [2] 67 d5 [2] 65 d4 [2] 7e d2 [2] 62 d5 [2] 7e fa }

  condition:
    any of them
}