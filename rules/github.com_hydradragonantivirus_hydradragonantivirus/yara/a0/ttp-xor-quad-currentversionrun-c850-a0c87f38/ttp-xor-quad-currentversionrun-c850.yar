rule TTP_XOR_QUAD_CurrentVersionRun_c850 {
  strings:
    $key_c850 = { 9b 3f [2] bf 31 [2] 94 1d [2] ba 3f [2] ae 24 [2] a1 3e [2] bf 23 [2] bd 22 [2] a6 24 [2] ba 23 [2] a6 0c }

  condition:
    any of them
}