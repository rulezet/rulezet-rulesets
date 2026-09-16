rule TTP_XOR_QUAD_CurrentVersionRun_c8f4 {
  strings:
    $key_c8f4 = { 9b 9b [2] bf 95 [2] 94 b9 [2] ba 9b [2] ae 80 [2] a1 9a [2] bf 87 [2] bd 86 [2] a6 80 [2] ba 87 [2] a6 a8 }

  condition:
    any of them
}