rule TTP_XOR_QUAD_CurrentVersionRun_45e1 {
  strings:
    $key_45e1 = { 16 8e [2] 32 80 [2] 19 ac [2] 37 8e [2] 23 95 [2] 2c 8f [2] 32 92 [2] 30 93 [2] 2b 95 [2] 37 92 [2] 2b bd }

  condition:
    any of them
}