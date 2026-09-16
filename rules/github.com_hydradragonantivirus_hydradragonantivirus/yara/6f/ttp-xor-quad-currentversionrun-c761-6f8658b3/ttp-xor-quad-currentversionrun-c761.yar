rule TTP_XOR_QUAD_CurrentVersionRun_c761 {
  strings:
    $key_c761 = { 94 0e [2] b0 00 [2] 9b 2c [2] b5 0e [2] a1 15 [2] ae 0f [2] b0 12 [2] b2 13 [2] a9 15 [2] b5 12 [2] a9 3d }

  condition:
    any of them
}