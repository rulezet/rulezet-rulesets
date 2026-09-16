rule TTP_XOR_QUAD_CurrentVersionRun_c61b {
  strings:
    $key_c61b = { 95 74 [2] b1 7a [2] 9a 56 [2] b4 74 [2] a0 6f [2] af 75 [2] b1 68 [2] b3 69 [2] a8 6f [2] b4 68 [2] a8 47 }

  condition:
    any of them
}