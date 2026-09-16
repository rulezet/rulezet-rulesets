rule TTP_XOR_QUAD_CurrentVersionRun_d461 {
  strings:
    $key_d461 = { 87 0e [2] a3 00 [2] 88 2c [2] a6 0e [2] b2 15 [2] bd 0f [2] a3 12 [2] a1 13 [2] ba 15 [2] a6 12 [2] ba 3d }

  condition:
    any of them
}