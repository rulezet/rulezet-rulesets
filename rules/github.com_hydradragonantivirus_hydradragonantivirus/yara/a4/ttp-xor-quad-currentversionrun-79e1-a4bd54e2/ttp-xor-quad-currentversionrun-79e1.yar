rule TTP_XOR_QUAD_CurrentVersionRun_79e1 {
  strings:
    $key_79e1 = { 2a 8e [2] 0e 80 [2] 25 ac [2] 0b 8e [2] 1f 95 [2] 10 8f [2] 0e 92 [2] 0c 93 [2] 17 95 [2] 0b 92 [2] 17 bd }

  condition:
    any of them
}