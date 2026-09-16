rule TTP_XOR_QUAD_CurrentVersionRun_c661 {
  strings:
    $key_c661 = { 95 0e [2] b1 00 [2] 9a 2c [2] b4 0e [2] a0 15 [2] af 0f [2] b1 12 [2] b3 13 [2] a8 15 [2] b4 12 [2] a8 3d }

  condition:
    any of them
}