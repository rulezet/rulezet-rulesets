rule TTP_XOR_QUAD_CurrentVersionRun_60e1 {
  strings:
    $key_60e1 = { 33 8e [2] 17 80 [2] 3c ac [2] 12 8e [2] 06 95 [2] 09 8f [2] 17 92 [2] 15 93 [2] 0e 95 [2] 12 92 [2] 0e bd }

  condition:
    any of them
}