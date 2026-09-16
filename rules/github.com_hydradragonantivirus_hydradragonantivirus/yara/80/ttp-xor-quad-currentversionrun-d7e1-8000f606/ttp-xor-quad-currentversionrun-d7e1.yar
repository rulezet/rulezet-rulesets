rule TTP_XOR_QUAD_CurrentVersionRun_d7e1 {
  strings:
    $key_d7e1 = { 84 8e [2] a0 80 [2] 8b ac [2] a5 8e [2] b1 95 [2] be 8f [2] a0 92 [2] a2 93 [2] b9 95 [2] a5 92 [2] b9 bd }

  condition:
    any of them
}