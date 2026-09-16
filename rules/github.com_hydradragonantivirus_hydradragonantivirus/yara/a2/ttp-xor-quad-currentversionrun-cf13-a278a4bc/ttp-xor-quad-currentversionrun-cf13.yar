rule TTP_XOR_QUAD_CurrentVersionRun_cf13 {
  strings:
    $key_cf13 = { 9c 7c [2] b8 72 [2] 93 5e [2] bd 7c [2] a9 67 [2] a6 7d [2] b8 60 [2] ba 61 [2] a1 67 [2] bd 60 [2] a1 4f }

  condition:
    any of them
}