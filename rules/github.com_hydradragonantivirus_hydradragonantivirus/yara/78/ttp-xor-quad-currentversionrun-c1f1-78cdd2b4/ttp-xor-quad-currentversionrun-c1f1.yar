rule TTP_XOR_QUAD_CurrentVersionRun_c1f1 {
  strings:
    $key_c1f1 = { 92 9e [2] b6 90 [2] 9d bc [2] b3 9e [2] a7 85 [2] a8 9f [2] b6 82 [2] b4 83 [2] af 85 [2] b3 82 [2] af ad }

  condition:
    any of them
}