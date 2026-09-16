rule TTP_XOR_QUAD_CurrentVersionRun_c1e1 {
  strings:
    $key_c1e1 = { 92 8e [2] b6 80 [2] 9d ac [2] b3 8e [2] a7 95 [2] a8 8f [2] b6 92 [2] b4 93 [2] af 95 [2] b3 92 [2] af bd }

  condition:
    any of them
}