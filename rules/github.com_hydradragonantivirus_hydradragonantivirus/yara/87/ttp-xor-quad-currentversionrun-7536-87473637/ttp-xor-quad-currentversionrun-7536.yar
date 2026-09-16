rule TTP_XOR_QUAD_CurrentVersionRun_7536 {
  strings:
    $key_7536 = { 26 59 [2] 02 57 [2] 29 7b [2] 07 59 [2] 13 42 [2] 1c 58 [2] 02 45 [2] 00 44 [2] 1b 42 [2] 07 45 [2] 1b 6a }

  condition:
    any of them
}