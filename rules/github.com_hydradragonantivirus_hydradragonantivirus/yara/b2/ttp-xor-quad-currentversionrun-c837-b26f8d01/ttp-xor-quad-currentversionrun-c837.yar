rule TTP_XOR_QUAD_CurrentVersionRun_c837 {
  strings:
    $key_c837 = { 9b 58 [2] bf 56 [2] 94 7a [2] ba 58 [2] ae 43 [2] a1 59 [2] bf 44 [2] bd 45 [2] a6 43 [2] ba 44 [2] a6 6b }

  condition:
    any of them
}