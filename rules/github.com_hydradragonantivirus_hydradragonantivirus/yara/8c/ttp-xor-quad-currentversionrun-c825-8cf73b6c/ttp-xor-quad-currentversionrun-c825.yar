rule TTP_XOR_QUAD_CurrentVersionRun_c825 {
  strings:
    $key_c825 = { 9b 4a [2] bf 44 [2] 94 68 [2] ba 4a [2] ae 51 [2] a1 4b [2] bf 56 [2] bd 57 [2] a6 51 [2] ba 56 [2] a6 79 }

  condition:
    any of them
}