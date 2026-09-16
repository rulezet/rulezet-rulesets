rule TTP_XOR_QUAD_CurrentVersionRun_7de1 {
  strings:
    $key_7de1 = { 2e 8e [2] 0a 80 [2] 21 ac [2] 0f 8e [2] 1b 95 [2] 14 8f [2] 0a 92 [2] 08 93 [2] 13 95 [2] 0f 92 [2] 13 bd }

  condition:
    any of them
}