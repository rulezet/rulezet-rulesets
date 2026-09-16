rule TTP_XOR_QUAD_CurrentVersionRun_c823 {
  strings:
    $key_c823 = { 9b 4c [2] bf 42 [2] 94 6e [2] ba 4c [2] ae 57 [2] a1 4d [2] bf 50 [2] bd 51 [2] a6 57 [2] ba 50 [2] a6 7f }

  condition:
    any of them
}