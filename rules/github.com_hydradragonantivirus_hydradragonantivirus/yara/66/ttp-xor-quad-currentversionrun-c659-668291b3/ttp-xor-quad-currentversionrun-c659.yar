rule TTP_XOR_QUAD_CurrentVersionRun_c659 {
  strings:
    $key_c659 = { 95 36 [2] b1 38 [2] 9a 14 [2] b4 36 [2] a0 2d [2] af 37 [2] b1 2a [2] b3 2b [2] a8 2d [2] b4 2a [2] a8 05 }

  condition:
    any of them
}