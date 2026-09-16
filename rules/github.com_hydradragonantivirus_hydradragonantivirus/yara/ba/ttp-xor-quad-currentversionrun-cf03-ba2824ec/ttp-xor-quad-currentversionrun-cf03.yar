rule TTP_XOR_QUAD_CurrentVersionRun_cf03 {
  strings:
    $key_cf03 = { 9c 6c [2] b8 62 [2] 93 4e [2] bd 6c [2] a9 77 [2] a6 6d [2] b8 70 [2] ba 71 [2] a1 77 [2] bd 70 [2] a1 5f }

  condition:
    any of them
}