rule TTP_XOR_QUAD_CurrentVersionRun_30e1 {
  strings:
    $key_30e1 = { 63 8e [2] 47 80 [2] 6c ac [2] 42 8e [2] 56 95 [2] 59 8f [2] 47 92 [2] 45 93 [2] 5e 95 [2] 42 92 [2] 5e bd }

  condition:
    any of them
}