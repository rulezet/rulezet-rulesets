rule TTP_XOR_QUAD_CurrentVersionRun_c561 {
  strings:
    $key_c561 = { 96 0e [2] b2 00 [2] 99 2c [2] b7 0e [2] a3 15 [2] ac 0f [2] b2 12 [2] b0 13 [2] ab 15 [2] b7 12 [2] ab 3d }

  condition:
    any of them
}