rule TTP_XOR_QUAD_CurrentVersionRun_f9e1 {
  strings:
    $key_f9e1 = { aa 8e [2] 8e 80 [2] a5 ac [2] 8b 8e [2] 9f 95 [2] 90 8f [2] 8e 92 [2] 8c 93 [2] 97 95 [2] 8b 92 [2] 97 bd }

  condition:
    any of them
}