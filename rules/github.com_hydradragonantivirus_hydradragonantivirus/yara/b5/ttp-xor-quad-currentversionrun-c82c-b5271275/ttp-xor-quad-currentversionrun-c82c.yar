rule TTP_XOR_QUAD_CurrentVersionRun_c82c {
  strings:
    $key_c82c = { 9b 43 [2] bf 4d [2] 94 61 [2] ba 43 [2] ae 58 [2] a1 42 [2] bf 5f [2] bd 5e [2] a6 58 [2] ba 5f [2] a6 70 }

  condition:
    any of them
}