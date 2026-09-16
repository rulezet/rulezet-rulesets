rule TTP_XOR_QUAD_CurrentVersionRun_10e1 {
  strings:
    $key_10e1 = { 43 8e [2] 67 80 [2] 4c ac [2] 62 8e [2] 76 95 [2] 79 8f [2] 67 92 [2] 65 93 [2] 7e 95 [2] 62 92 [2] 7e bd }

  condition:
    any of them
}