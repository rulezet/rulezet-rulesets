rule TTP_XOR_QUAD_CurrentVersionRun_c8e9 {
  strings:
    $key_c8e9 = { 9b 86 [2] bf 88 [2] 94 a4 [2] ba 86 [2] ae 9d [2] a1 87 [2] bf 9a [2] bd 9b [2] a6 9d [2] ba 9a [2] a6 b5 }

  condition:
    any of them
}