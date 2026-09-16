rule TTP_XOR_QUAD_CurrentVersionRun_40e1 {
  strings:
    $key_40e1 = { 13 8e [2] 37 80 [2] 1c ac [2] 32 8e [2] 26 95 [2] 29 8f [2] 37 92 [2] 35 93 [2] 2e 95 [2] 32 92 [2] 2e bd }

  condition:
    any of them
}