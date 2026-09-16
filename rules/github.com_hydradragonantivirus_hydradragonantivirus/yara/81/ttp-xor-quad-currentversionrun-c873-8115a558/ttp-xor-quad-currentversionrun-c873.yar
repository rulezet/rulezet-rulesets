rule TTP_XOR_QUAD_CurrentVersionRun_c873 {
  strings:
    $key_c873 = { 9b 1c [2] bf 12 [2] 94 3e [2] ba 1c [2] ae 07 [2] a1 1d [2] bf 00 [2] bd 01 [2] a6 07 [2] ba 00 [2] a6 2f }

  condition:
    any of them
}