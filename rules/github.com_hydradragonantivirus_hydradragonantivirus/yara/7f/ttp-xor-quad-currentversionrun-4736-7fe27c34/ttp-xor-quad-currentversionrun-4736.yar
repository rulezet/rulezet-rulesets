rule TTP_XOR_QUAD_CurrentVersionRun_4736 {
  strings:
    $key_4736 = { 14 59 [2] 30 57 [2] 1b 7b [2] 35 59 [2] 21 42 [2] 2e 58 [2] 30 45 [2] 32 44 [2] 29 42 [2] 35 45 [2] 29 6a }

  condition:
    any of them
}