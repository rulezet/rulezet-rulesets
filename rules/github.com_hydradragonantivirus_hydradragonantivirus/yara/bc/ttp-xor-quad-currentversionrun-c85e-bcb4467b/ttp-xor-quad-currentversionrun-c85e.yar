rule TTP_XOR_QUAD_CurrentVersionRun_c85e {
  strings:
    $key_c85e = { 9b 31 [2] bf 3f [2] 94 13 [2] ba 31 [2] ae 2a [2] a1 30 [2] bf 2d [2] bd 2c [2] a6 2a [2] ba 2d [2] a6 02 }

  condition:
    any of them
}