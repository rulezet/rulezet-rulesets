rule TTP_XOR_QUAD_CurrentVersionRun_0746 {
  strings:
    $key_0746 = { 54 29 [2] 70 27 [2] 5b 0b [2] 75 29 [2] 61 32 [2] 6e 28 [2] 70 35 [2] 72 34 [2] 69 32 [2] 75 35 [2] 69 1a }

  condition:
    any of them
}