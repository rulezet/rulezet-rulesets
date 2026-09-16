rule TTP_XOR_QUAD_CurrentVersionRun_f6e1 {
  strings:
    $key_f6e1 = { a5 8e [2] 81 80 [2] aa ac [2] 84 8e [2] 90 95 [2] 9f 8f [2] 81 92 [2] 83 93 [2] 98 95 [2] 84 92 [2] 98 bd }

  condition:
    any of them
}