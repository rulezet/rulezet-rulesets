rule TTP_XOR_QUAD_CurrentVersionRun_cf63 {
  strings:
    $key_cf63 = { 9c 0c [2] b8 02 [2] 93 2e [2] bd 0c [2] a9 17 [2] a6 0d [2] b8 10 [2] ba 11 [2] a1 17 [2] bd 10 [2] a1 3f }

  condition:
    any of them
}