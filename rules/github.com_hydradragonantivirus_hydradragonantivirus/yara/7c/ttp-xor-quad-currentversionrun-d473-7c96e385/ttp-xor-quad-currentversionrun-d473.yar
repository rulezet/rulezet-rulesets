rule TTP_XOR_QUAD_CurrentVersionRun_d473 {
  strings:
    $key_d473 = { 87 1c [2] a3 12 [2] 88 3e [2] a6 1c [2] b2 07 [2] bd 1d [2] a3 00 [2] a1 01 [2] ba 07 [2] a6 00 [2] ba 2f }

  condition:
    any of them
}