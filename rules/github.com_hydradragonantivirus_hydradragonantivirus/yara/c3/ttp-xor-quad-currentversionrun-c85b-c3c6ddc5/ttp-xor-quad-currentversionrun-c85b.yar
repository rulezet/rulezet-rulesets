rule TTP_XOR_QUAD_CurrentVersionRun_c85b {
  strings:
    $key_c85b = { 9b 34 [2] bf 3a [2] 94 16 [2] ba 34 [2] ae 2f [2] a1 35 [2] bf 28 [2] bd 29 [2] a6 2f [2] ba 28 [2] a6 07 }

  condition:
    any of them
}