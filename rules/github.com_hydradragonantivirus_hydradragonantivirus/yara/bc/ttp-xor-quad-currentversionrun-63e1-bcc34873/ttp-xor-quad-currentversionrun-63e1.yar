rule TTP_XOR_QUAD_CurrentVersionRun_63e1 {
  strings:
    $key_63e1 = { 30 8e [2] 14 80 [2] 3f ac [2] 11 8e [2] 05 95 [2] 0a 8f [2] 14 92 [2] 16 93 [2] 0d 95 [2] 11 92 [2] 0d bd }

  condition:
    any of them
}