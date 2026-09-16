rule TTP_XOR_QUAD_CurrentVersionRun_e8e1 {
  strings:
    $key_e8e1 = { bb 8e [2] 9f 80 [2] b4 ac [2] 9a 8e [2] 8e 95 [2] 81 8f [2] 9f 92 [2] 9d 93 [2] 86 95 [2] 9a 92 [2] 86 bd }

  condition:
    any of them
}