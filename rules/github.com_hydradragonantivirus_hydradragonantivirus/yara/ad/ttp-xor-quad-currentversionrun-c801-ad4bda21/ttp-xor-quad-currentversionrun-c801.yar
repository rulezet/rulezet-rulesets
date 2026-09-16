rule TTP_XOR_QUAD_CurrentVersionRun_c801 {
  strings:
    $key_c801 = { 9b 6e [2] bf 60 [2] 94 4c [2] ba 6e [2] ae 75 [2] a1 6f [2] bf 72 [2] bd 73 [2] a6 75 [2] ba 72 [2] a6 5d }

  condition:
    any of them
}