rule TTP_XOR_QUAD_CurrentVersionRun_cf50 {
  strings:
    $key_cf50 = { 9c 3f [2] b8 31 [2] 93 1d [2] bd 3f [2] a9 24 [2] a6 3e [2] b8 23 [2] ba 22 [2] a1 24 [2] bd 23 [2] a1 0c }

  condition:
    any of them
}