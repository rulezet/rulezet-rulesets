rule TTP_XOR_QUAD_CurrentVersionRun_c846 {
  strings:
    $key_c846 = { 9b 29 [2] bf 27 [2] 94 0b [2] ba 29 [2] ae 32 [2] a1 28 [2] bf 35 [2] bd 34 [2] a6 32 [2] ba 35 [2] a6 1a }

  condition:
    any of them
}