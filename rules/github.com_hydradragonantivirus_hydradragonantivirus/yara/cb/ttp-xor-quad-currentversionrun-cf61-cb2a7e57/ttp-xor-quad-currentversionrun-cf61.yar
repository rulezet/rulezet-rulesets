rule TTP_XOR_QUAD_CurrentVersionRun_cf61 {
  strings:
    $key_cf61 = { 9c 0e [2] b8 00 [2] 93 2c [2] bd 0e [2] a9 15 [2] a6 0f [2] b8 12 [2] ba 13 [2] a1 15 [2] bd 12 [2] a1 3d }

  condition:
    any of them
}