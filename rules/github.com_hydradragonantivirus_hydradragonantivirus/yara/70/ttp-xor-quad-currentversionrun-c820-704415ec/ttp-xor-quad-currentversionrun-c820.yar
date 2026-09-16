rule TTP_XOR_QUAD_CurrentVersionRun_c820 {
  strings:
    $key_c820 = { 9b 4f [2] bf 41 [2] 94 6d [2] ba 4f [2] ae 54 [2] a1 4e [2] bf 53 [2] bd 52 [2] a6 54 [2] ba 53 [2] a6 7c }

  condition:
    any of them
}