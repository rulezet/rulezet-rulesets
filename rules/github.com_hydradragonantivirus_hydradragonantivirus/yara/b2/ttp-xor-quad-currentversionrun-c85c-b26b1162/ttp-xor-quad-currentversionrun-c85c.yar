rule TTP_XOR_QUAD_CurrentVersionRun_c85c {
  strings:
    $key_c85c = { 9b 33 [2] bf 3d [2] 94 11 [2] ba 33 [2] ae 28 [2] a1 32 [2] bf 2f [2] bd 2e [2] a6 28 [2] ba 2f [2] a6 00 }

  condition:
    any of them
}