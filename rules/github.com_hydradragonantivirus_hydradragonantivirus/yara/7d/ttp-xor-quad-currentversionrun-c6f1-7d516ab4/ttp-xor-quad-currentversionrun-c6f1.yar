rule TTP_XOR_QUAD_CurrentVersionRun_c6f1 {
  strings:
    $key_c6f1 = { 95 9e [2] b1 90 [2] 9a bc [2] b4 9e [2] a0 85 [2] af 9f [2] b1 82 [2] b3 83 [2] a8 85 [2] b4 82 [2] a8 ad }

  condition:
    any of them
}