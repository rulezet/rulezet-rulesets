rule TTP_XOR_QUAD_CurrentVersionRun_5ee1 {
  strings:
    $key_5ee1 = { 0d 8e [2] 29 80 [2] 02 ac [2] 2c 8e [2] 38 95 [2] 37 8f [2] 29 92 [2] 2b 93 [2] 30 95 [2] 2c 92 [2] 30 bd }

  condition:
    any of them
}