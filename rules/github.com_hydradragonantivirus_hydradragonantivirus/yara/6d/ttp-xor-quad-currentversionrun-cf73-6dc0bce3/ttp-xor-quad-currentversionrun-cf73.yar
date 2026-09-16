rule TTP_XOR_QUAD_CurrentVersionRun_cf73 {
  strings:
    $key_cf73 = { 9c 1c [2] b8 12 [2] 93 3e [2] bd 1c [2] a9 07 [2] a6 1d [2] b8 00 [2] ba 01 [2] a1 07 [2] bd 00 [2] a1 2f }

  condition:
    any of them
}