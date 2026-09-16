rule TTP_XOR_QUAD_CurrentVersionRun_c860 {
  strings:
    $key_c860 = { 9b 0f [2] bf 01 [2] 94 2d [2] ba 0f [2] ae 14 [2] a1 0e [2] bf 13 [2] bd 12 [2] a6 14 [2] ba 13 [2] a6 3c }

  condition:
    any of them
}