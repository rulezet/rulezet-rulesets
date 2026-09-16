rule TTP_XOR_QUAD_CurrentVersionRun_c667 {
  strings:
    $key_c667 = { 95 08 [2] b1 06 [2] 9a 2a [2] b4 08 [2] a0 13 [2] af 09 [2] b1 14 [2] b3 15 [2] a8 13 [2] b4 14 [2] a8 3b }

  condition:
    any of them
}