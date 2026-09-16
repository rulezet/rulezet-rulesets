rule TTP_XOR_QUAD_CurrentVersionRun_6ce1 {
  strings:
    $key_6ce1 = { 3f 8e [2] 1b 80 [2] 30 ac [2] 1e 8e [2] 0a 95 [2] 05 8f [2] 1b 92 [2] 19 93 [2] 02 95 [2] 1e 92 [2] 02 bd }

  condition:
    any of them
}