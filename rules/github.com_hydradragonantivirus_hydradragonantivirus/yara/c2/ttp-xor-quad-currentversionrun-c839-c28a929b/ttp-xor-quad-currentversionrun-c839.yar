rule TTP_XOR_QUAD_CurrentVersionRun_c839 {
  strings:
    $key_c839 = { 9b 56 [2] bf 58 [2] 94 74 [2] ba 56 [2] ae 4d [2] a1 57 [2] bf 4a [2] bd 4b [2] a6 4d [2] ba 4a [2] a6 65 }

  condition:
    any of them
}