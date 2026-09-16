rule TTP_XOR_QUAD_CurrentVersionRun_f0e1 {
  strings:
    $key_f0e1 = { a3 8e [2] 87 80 [2] ac ac [2] 82 8e [2] 96 95 [2] 99 8f [2] 87 92 [2] 85 93 [2] 9e 95 [2] 82 92 [2] 9e bd }

  condition:
    any of them
}