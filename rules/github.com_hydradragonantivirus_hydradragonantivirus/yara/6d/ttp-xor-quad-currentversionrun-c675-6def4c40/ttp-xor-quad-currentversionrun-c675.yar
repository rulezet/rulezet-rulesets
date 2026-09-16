rule TTP_XOR_QUAD_CurrentVersionRun_c675 {
  strings:
    $key_c675 = { 95 1a [2] b1 14 [2] 9a 38 [2] b4 1a [2] a0 01 [2] af 1b [2] b1 06 [2] b3 07 [2] a8 01 [2] b4 06 [2] a8 29 }

  condition:
    any of them
}