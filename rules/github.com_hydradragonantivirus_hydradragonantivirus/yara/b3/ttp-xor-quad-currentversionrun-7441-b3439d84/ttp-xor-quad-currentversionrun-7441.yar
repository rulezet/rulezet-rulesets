rule TTP_XOR_QUAD_CurrentVersionRun_7441 {
  strings:
    $key_7441 = { 27 2e [2] 03 20 [2] 28 0c [2] 06 2e [2] 12 35 [2] 1d 2f [2] 03 32 [2] 01 33 [2] 1a 35 [2] 06 32 [2] 1a 1d }

  condition:
    any of them
}