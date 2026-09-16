rule TTP_XOR_QUAD_CurrentVersionRun_c674 {
  strings:
    $key_c674 = { 95 1b [2] b1 15 [2] 9a 39 [2] b4 1b [2] a0 00 [2] af 1a [2] b1 07 [2] b3 06 [2] a8 00 [2] b4 07 [2] a8 28 }

  condition:
    any of them
}