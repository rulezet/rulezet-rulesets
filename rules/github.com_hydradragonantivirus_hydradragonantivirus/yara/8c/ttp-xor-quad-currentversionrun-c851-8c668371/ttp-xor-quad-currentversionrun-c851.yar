rule TTP_XOR_QUAD_CurrentVersionRun_c851 {
  strings:
    $key_c851 = { 9b 3e [2] bf 30 [2] 94 1c [2] ba 3e [2] ae 25 [2] a1 3f [2] bf 22 [2] bd 23 [2] a6 25 [2] ba 22 [2] a6 0d }

  condition:
    any of them
}