rule TTP_XOR_QUAD_CurrentVersionRun_57e1 {
  strings:
    $key_57e1 = { 04 8e [2] 20 80 [2] 0b ac [2] 25 8e [2] 31 95 [2] 3e 8f [2] 20 92 [2] 22 93 [2] 39 95 [2] 25 92 [2] 39 bd }

  condition:
    any of them
}