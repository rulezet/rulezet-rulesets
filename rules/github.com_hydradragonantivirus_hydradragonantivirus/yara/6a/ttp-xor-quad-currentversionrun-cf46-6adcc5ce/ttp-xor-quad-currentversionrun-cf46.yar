rule TTP_XOR_QUAD_CurrentVersionRun_cf46 {
  strings:
    $key_cf46 = { 9c 29 [2] b8 27 [2] 93 0b [2] bd 29 [2] a9 32 [2] a6 28 [2] b8 35 [2] ba 34 [2] a1 32 [2] bd 35 [2] a1 1a }

  condition:
    any of them
}