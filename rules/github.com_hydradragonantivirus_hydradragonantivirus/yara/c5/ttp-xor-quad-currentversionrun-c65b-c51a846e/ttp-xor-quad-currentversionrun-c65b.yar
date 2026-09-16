rule TTP_XOR_QUAD_CurrentVersionRun_c65b {
  strings:
    $key_c65b = { 95 34 [2] b1 3a [2] 9a 16 [2] b4 34 [2] a0 2f [2] af 35 [2] b1 28 [2] b3 29 [2] a8 2f [2] b4 28 [2] a8 07 }

  condition:
    any of them
}