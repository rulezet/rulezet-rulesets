rule TTP_XOR_QUAD_CurrentVersionRun_c84d {
  strings:
    $key_c84d = { 9b 22 [2] bf 2c [2] 94 00 [2] ba 22 [2] ae 39 [2] a1 23 [2] bf 3e [2] bd 3f [2] a6 39 [2] ba 3e [2] a6 11 }

  condition:
    any of them
}