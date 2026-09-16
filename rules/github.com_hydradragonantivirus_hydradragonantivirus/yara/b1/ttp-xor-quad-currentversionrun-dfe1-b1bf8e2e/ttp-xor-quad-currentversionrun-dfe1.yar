rule TTP_XOR_QUAD_CurrentVersionRun_dfe1 {
  strings:
    $key_dfe1 = { 8c 8e [2] a8 80 [2] 83 ac [2] ad 8e [2] b9 95 [2] b6 8f [2] a8 92 [2] aa 93 [2] b1 95 [2] ad 92 [2] b1 bd }

  condition:
    any of them
}