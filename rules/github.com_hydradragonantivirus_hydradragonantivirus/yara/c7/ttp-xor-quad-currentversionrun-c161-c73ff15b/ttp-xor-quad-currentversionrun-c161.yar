rule TTP_XOR_QUAD_CurrentVersionRun_c161 {
  strings:
    $key_c161 = { 92 0e [2] b6 00 [2] 9d 2c [2] b3 0e [2] a7 15 [2] a8 0f [2] b6 12 [2] b4 13 [2] af 15 [2] b3 12 [2] af 3d }

  condition:
    any of them
}