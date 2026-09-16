rule TTP_XOR_QUAD_CurrentVersionRun_c82e {
  strings:
    $key_c82e = { 9b 41 [2] bf 4f [2] 94 63 [2] ba 41 [2] ae 5a [2] a1 40 [2] bf 5d [2] bd 5c [2] a6 5a [2] ba 5d [2] a6 72 }

  condition:
    any of them
}