rule TTP_XOR_QUAD_CurrentVersionRun_0441 {
  strings:
    $key_0441 = { 57 2e [2] 73 20 [2] 58 0c [2] 76 2e [2] 62 35 [2] 6d 2f [2] 73 32 [2] 71 33 [2] 6a 35 [2] 76 32 [2] 6a 1d }

  condition:
    any of them
}