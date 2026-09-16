rule TTP_XOR_QUAD_CurrentVersionRun_d453 {
  strings:
    $key_d453 = { 87 3c [2] a3 32 [2] 88 1e [2] a6 3c [2] b2 27 [2] bd 3d [2] a3 20 [2] a1 21 [2] ba 27 [2] a6 20 [2] ba 0f }

  condition:
    any of them
}