rule TTP_XOR_QUAD_CurrentVersionRun_c809 {
  strings:
    $key_c809 = { 9b 66 [2] bf 68 [2] 94 44 [2] ba 66 [2] ae 7d [2] a1 67 [2] bf 7a [2] bd 7b [2] a6 7d [2] ba 7a [2] a6 55 }

  condition:
    any of them
}