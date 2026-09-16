rule TTP_XOR_QUAD_CurrentVersionRun_4de1 {
  strings:
    $key_4de1 = { 1e 8e [2] 3a 80 [2] 11 ac [2] 3f 8e [2] 2b 95 [2] 24 8f [2] 3a 92 [2] 38 93 [2] 23 95 [2] 3f 92 [2] 23 bd }

  condition:
    any of them
}