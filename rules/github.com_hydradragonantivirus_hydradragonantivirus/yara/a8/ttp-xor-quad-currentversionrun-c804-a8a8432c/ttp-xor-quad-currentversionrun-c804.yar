rule TTP_XOR_QUAD_CurrentVersionRun_c804 {
  strings:
    $key_c804 = { 9b 6b [2] bf 65 [2] 94 49 [2] ba 6b [2] ae 70 [2] a1 6a [2] bf 77 [2] bd 76 [2] a6 70 [2] ba 77 [2] a6 58 }

  condition:
    any of them
}