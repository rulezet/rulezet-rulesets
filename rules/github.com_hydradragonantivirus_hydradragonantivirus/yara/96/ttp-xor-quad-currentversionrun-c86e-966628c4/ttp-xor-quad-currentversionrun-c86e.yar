rule TTP_XOR_QUAD_CurrentVersionRun_c86e {
  strings:
    $key_c86e = { 9b 01 [2] bf 0f [2] 94 23 [2] ba 01 [2] ae 1a [2] a1 00 [2] bf 1d [2] bd 1c [2] a6 1a [2] ba 1d [2] a6 32 }

  condition:
    any of them
}