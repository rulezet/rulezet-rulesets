rule TTP_XOR_QUAD_CurrentVersionRun_b4e1 {
  strings:
    $key_b4e1 = { e7 8e [2] c3 80 [2] e8 ac [2] c6 8e [2] d2 95 [2] dd 8f [2] c3 92 [2] c1 93 [2] da 95 [2] c6 92 [2] da bd }

  condition:
    any of them
}