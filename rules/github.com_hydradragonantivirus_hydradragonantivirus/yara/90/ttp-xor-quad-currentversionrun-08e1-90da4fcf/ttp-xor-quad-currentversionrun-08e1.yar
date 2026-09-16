rule TTP_XOR_QUAD_CurrentVersionRun_08e1 {
  strings:
    $key_08e1 = { 5b 8e [2] 7f 80 [2] 54 ac [2] 7a 8e [2] 6e 95 [2] 61 8f [2] 7f 92 [2] 7d 93 [2] 66 95 [2] 7a 92 [2] 66 bd }

  condition:
    any of them
}