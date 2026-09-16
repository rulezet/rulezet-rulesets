rule TTP_XOR_QUAD_CurrentVersionRun_2ce1 {
  strings:
    $key_2ce1 = { 7f 8e [2] 5b 80 [2] 70 ac [2] 5e 8e [2] 4a 95 [2] 45 8f [2] 5b 92 [2] 59 93 [2] 42 95 [2] 5e 92 [2] 42 bd }

  condition:
    any of them
}