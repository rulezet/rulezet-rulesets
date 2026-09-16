rule TTP_XOR_QUAD_CurrentVersionRun_cf53 {
  strings:
    $key_cf53 = { 9c 3c [2] b8 32 [2] 93 1e [2] bd 3c [2] a9 27 [2] a6 3d [2] b8 20 [2] ba 21 [2] a1 27 [2] bd 20 [2] a1 0f }

  condition:
    any of them
}