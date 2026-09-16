rule TTP_XOR_QUAD_CurrentVersionRun_cf23 {
  strings:
    $key_cf23 = { 9c 4c [2] b8 42 [2] 93 6e [2] bd 4c [2] a9 57 [2] a6 4d [2] b8 50 [2] ba 51 [2] a1 57 [2] bd 50 [2] a1 7f }

  condition:
    any of them
}