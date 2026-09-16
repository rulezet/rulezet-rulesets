rule TTP_XOR_QUAD_CurrentVersionRun_c818 {
  strings:
    $key_c818 = { 9b 77 [2] bf 79 [2] 94 55 [2] ba 77 [2] ae 6c [2] a1 76 [2] bf 6b [2] bd 6a [2] a6 6c [2] ba 6b [2] a6 44 }

  condition:
    any of them
}