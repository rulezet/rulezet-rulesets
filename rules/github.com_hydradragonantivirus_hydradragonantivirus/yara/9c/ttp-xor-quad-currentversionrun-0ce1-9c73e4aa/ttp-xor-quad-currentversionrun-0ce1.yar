rule TTP_XOR_QUAD_CurrentVersionRun_0ce1 {
  strings:
    $key_0ce1 = { 5f 8e [2] 7b 80 [2] 50 ac [2] 7e 8e [2] 6a 95 [2] 65 8f [2] 7b 92 [2] 79 93 [2] 62 95 [2] 7e 92 [2] 62 bd }

  condition:
    any of them
}