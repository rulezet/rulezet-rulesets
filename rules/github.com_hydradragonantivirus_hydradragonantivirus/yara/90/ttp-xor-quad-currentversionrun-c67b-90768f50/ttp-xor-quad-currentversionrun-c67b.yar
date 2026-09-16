rule TTP_XOR_QUAD_CurrentVersionRun_c67b {
  strings:
    $key_c67b = { 95 14 [2] b1 1a [2] 9a 36 [2] b4 14 [2] a0 0f [2] af 15 [2] b1 08 [2] b3 09 [2] a8 0f [2] b4 08 [2] a8 27 }

  condition:
    any of them
}