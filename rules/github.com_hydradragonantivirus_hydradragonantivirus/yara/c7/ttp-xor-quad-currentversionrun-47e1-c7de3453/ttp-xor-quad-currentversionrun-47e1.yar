rule TTP_XOR_QUAD_CurrentVersionRun_47e1 {
  strings:
    $key_47e1 = { 14 8e [2] 30 80 [2] 1b ac [2] 35 8e [2] 21 95 [2] 2e 8f [2] 30 92 [2] 32 93 [2] 29 95 [2] 35 92 [2] 29 bd }

  condition:
    any of them
}