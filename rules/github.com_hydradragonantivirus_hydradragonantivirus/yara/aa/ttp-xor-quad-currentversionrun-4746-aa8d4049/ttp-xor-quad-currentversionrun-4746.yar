rule TTP_XOR_QUAD_CurrentVersionRun_4746 {
  strings:
    $key_4746 = { 14 29 [2] 30 27 [2] 1b 0b [2] 35 29 [2] 21 32 [2] 2e 28 [2] 30 35 [2] 32 34 [2] 29 32 [2] 35 35 [2] 29 1a }

  condition:
    any of them
}