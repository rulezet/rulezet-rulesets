rule TTP_XOR_QUAD_CurrentVersionRun_00e1 {
  strings:
    $key_00e1 = { 53 8e [2] 77 80 [2] 5c ac [2] 72 8e [2] 66 95 [2] 69 8f [2] 77 92 [2] 75 93 [2] 6e 95 [2] 72 92 [2] 6e bd }

  condition:
    any of them
}