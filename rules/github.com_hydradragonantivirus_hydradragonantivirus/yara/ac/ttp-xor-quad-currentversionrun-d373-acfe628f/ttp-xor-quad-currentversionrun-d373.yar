rule TTP_XOR_QUAD_CurrentVersionRun_d373 {
  strings:
    $key_d373 = { 80 1c [2] a4 12 [2] 8f 3e [2] a1 1c [2] b5 07 [2] ba 1d [2] a4 00 [2] a6 01 [2] bd 07 [2] a1 00 [2] bd 2f }

  condition:
    any of them
}