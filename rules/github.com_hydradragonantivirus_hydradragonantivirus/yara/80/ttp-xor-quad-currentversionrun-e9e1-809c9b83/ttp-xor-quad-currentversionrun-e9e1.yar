rule TTP_XOR_QUAD_CurrentVersionRun_e9e1 {
  strings:
    $key_e9e1 = { ba 8e [2] 9e 80 [2] b5 ac [2] 9b 8e [2] 8f 95 [2] 80 8f [2] 9e 92 [2] 9c 93 [2] 87 95 [2] 9b 92 [2] 87 bd }

  condition:
    any of them
}