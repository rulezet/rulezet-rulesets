rule TTP_XOR_QUAD_CurrentVersionRun_3ce1 {
  strings:
    $key_3ce1 = { 6f 8e [2] 4b 80 [2] 60 ac [2] 4e 8e [2] 5a 95 [2] 55 8f [2] 4b 92 [2] 49 93 [2] 52 95 [2] 4e 92 [2] 52 bd }

  condition:
    any of them
}