rule TTP_XOR_QUAD_CurrentVersionRun_c6fd {
  strings:
    $key_c6fd = { 95 92 [2] b1 9c [2] 9a b0 [2] b4 92 [2] a0 89 [2] af 93 [2] b1 8e [2] b3 8f [2] a8 89 [2] b4 8e [2] a8 a1 }

  condition:
    any of them
}