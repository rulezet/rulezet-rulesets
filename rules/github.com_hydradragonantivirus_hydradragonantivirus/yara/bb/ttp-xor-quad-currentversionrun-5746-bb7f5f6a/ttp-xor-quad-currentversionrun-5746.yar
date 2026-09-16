rule TTP_XOR_QUAD_CurrentVersionRun_5746 {
  strings:
    $key_5746 = { 04 29 [2] 20 27 [2] 0b 0b [2] 25 29 [2] 31 32 [2] 3e 28 [2] 20 35 [2] 22 34 [2] 39 32 [2] 25 35 [2] 39 1a }

  condition:
    any of them
}