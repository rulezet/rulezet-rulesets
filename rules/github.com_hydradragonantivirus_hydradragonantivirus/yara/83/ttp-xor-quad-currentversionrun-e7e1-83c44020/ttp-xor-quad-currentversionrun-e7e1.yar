rule TTP_XOR_QUAD_CurrentVersionRun_e7e1 {
  strings:
    $key_e7e1 = { b4 8e [2] 90 80 [2] bb ac [2] 95 8e [2] 81 95 [2] 8e 8f [2] 90 92 [2] 92 93 [2] 89 95 [2] 95 92 [2] 89 bd }

  condition:
    any of them
}