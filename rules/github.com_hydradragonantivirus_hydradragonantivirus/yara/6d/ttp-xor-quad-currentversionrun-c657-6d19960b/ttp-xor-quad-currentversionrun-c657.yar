rule TTP_XOR_QUAD_CurrentVersionRun_c657 {
  strings:
    $key_c657 = { 95 38 [2] b1 36 [2] 9a 1a [2] b4 38 [2] a0 23 [2] af 39 [2] b1 24 [2] b3 25 [2] a8 23 [2] b4 24 [2] a8 0b }

  condition:
    any of them
}