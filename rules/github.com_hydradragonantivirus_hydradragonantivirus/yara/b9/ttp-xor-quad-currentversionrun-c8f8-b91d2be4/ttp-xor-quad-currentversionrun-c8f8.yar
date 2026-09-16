rule TTP_XOR_QUAD_CurrentVersionRun_c8f8 {
  strings:
    $key_c8f8 = { 9b 97 [2] bf 99 [2] 94 b5 [2] ba 97 [2] ae 8c [2] a1 96 [2] bf 8b [2] bd 8a [2] a6 8c [2] ba 8b [2] a6 a4 }

  condition:
    any of them
}