rule TTP_XOR_QUAD_CurrentVersionRun_37e1 {
  strings:
    $key_37e1 = { 64 8e [2] 40 80 [2] 6b ac [2] 45 8e [2] 51 95 [2] 5e 8f [2] 40 92 [2] 42 93 [2] 59 95 [2] 45 92 [2] 59 bd }

  condition:
    any of them
}