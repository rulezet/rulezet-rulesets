rule TTP_XOR_QUAD_CurrentVersionRun_69e1 {
  strings:
    $key_69e1 = { 3a 8e [2] 1e 80 [2] 35 ac [2] 1b 8e [2] 0f 95 [2] 00 8f [2] 1e 92 [2] 1c 93 [2] 07 95 [2] 1b 92 [2] 07 bd }

  condition:
    any of them
}