rule TTP_XOR_QUAD_CurrentVersionRun_77e1 {
  strings:
    $key_77e1 = { 24 8e [2] 00 80 [2] 2b ac [2] 05 8e [2] 11 95 [2] 1e 8f [2] 00 92 [2] 02 93 [2] 19 95 [2] 05 92 [2] 19 bd }

  condition:
    any of them
}