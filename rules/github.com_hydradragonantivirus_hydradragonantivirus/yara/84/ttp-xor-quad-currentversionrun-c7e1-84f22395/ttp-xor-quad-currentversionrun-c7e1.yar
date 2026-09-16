rule TTP_XOR_QUAD_CurrentVersionRun_c7e1 {
  strings:
    $key_c7e1 = { 94 8e [2] b0 80 [2] 9b ac [2] b5 8e [2] a1 95 [2] ae 8f [2] b0 92 [2] b2 93 [2] a9 95 [2] b5 92 [2] a9 bd }

  condition:
    any of them
}