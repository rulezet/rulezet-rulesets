rule TTP_XOR_QUAD_CurrentVersionRun_56e1 {
  strings:
    $key_56e1 = { 05 8e [2] 21 80 [2] 0a ac [2] 24 8e [2] 30 95 [2] 3f 8f [2] 21 92 [2] 23 93 [2] 38 95 [2] 24 92 [2] 38 bd }

  condition:
    any of them
}