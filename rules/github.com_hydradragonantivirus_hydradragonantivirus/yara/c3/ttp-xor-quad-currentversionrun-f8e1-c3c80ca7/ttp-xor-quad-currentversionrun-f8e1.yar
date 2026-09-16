rule TTP_XOR_QUAD_CurrentVersionRun_f8e1 {
  strings:
    $key_f8e1 = { ab 8e [2] 8f 80 [2] a4 ac [2] 8a 8e [2] 9e 95 [2] 91 8f [2] 8f 92 [2] 8d 93 [2] 96 95 [2] 8a 92 [2] 96 bd }

  condition:
    any of them
}