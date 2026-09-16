rule TTP_XOR_QUAD_CurrentVersionRun_c8e8 {
  strings:
    $key_c8e8 = { 9b 87 [2] bf 89 [2] 94 a5 [2] ba 87 [2] ae 9c [2] a1 86 [2] bf 9b [2] bd 9a [2] a6 9c [2] ba 9b [2] a6 b4 }

  condition:
    any of them
}