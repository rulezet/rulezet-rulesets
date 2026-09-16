rule TTP_XOR_QUAD_CurrentVersionRun_cf66 {
  strings:
    $key_cf66 = { 9c 09 [2] b8 07 [2] 93 2b [2] bd 09 [2] a9 12 [2] a6 08 [2] b8 15 [2] ba 14 [2] a1 12 [2] bd 15 [2] a1 3a }

  condition:
    any of them
}