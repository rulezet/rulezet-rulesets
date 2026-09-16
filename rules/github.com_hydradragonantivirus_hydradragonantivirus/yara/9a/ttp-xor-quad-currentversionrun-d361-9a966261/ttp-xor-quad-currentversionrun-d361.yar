rule TTP_XOR_QUAD_CurrentVersionRun_d361 {
  strings:
    $key_d361 = { 80 0e [2] a4 00 [2] 8f 2c [2] a1 0e [2] b5 15 [2] ba 0f [2] a4 12 [2] a6 13 [2] bd 15 [2] a1 12 [2] bd 3d }

  condition:
    any of them
}