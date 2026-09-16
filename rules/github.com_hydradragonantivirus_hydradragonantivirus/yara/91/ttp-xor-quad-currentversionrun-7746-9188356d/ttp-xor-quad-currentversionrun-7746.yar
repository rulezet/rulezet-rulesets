rule TTP_XOR_QUAD_CurrentVersionRun_7746 {
  strings:
    $key_7746 = { 24 29 [2] 00 27 [2] 2b 0b [2] 05 29 [2] 11 32 [2] 1e 28 [2] 00 35 [2] 02 34 [2] 19 32 [2] 05 35 [2] 19 1a }

  condition:
    any of them
}