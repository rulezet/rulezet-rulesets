rule TTP_XOR_QUAD_CurrentVersionRun_dc61 {
  strings:
    $key_dc61 = { 8f 0e [2] ab 00 [2] 80 2c [2] ae 0e [2] ba 15 [2] b5 0f [2] ab 12 [2] a9 13 [2] b2 15 [2] ae 12 [2] b2 3d }

  condition:
    any of them
}