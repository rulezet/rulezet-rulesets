rule TTP_XOR_QUAD_CurrentVersionRun_c64b {
  strings:
    $key_c64b = { 95 24 [2] b1 2a [2] 9a 06 [2] b4 24 [2] a0 3f [2] af 25 [2] b1 38 [2] b3 39 [2] a8 3f [2] b4 38 [2] a8 17 }

  condition:
    any of them
}