rule TTP_XOR_QUAD_CurrentVersionRun_c848 {
  strings:
    $key_c848 = { 9b 27 [2] bf 29 [2] 94 05 [2] ba 27 [2] ae 3c [2] a1 26 [2] bf 3b [2] bd 3a [2] a6 3c [2] ba 3b [2] a6 14 }

  condition:
    any of them
}