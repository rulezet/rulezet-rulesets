rule TTP_XOR_QUAD_CurrentVersionRun_7fe1 {
  strings:
    $key_7fe1 = { 2c 8e [2] 08 80 [2] 23 ac [2] 0d 8e [2] 19 95 [2] 16 8f [2] 08 92 [2] 0a 93 [2] 11 95 [2] 0d 92 [2] 11 bd }

  condition:
    any of them
}