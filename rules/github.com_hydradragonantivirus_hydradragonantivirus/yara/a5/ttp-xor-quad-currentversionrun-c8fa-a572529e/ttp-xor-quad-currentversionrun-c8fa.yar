rule TTP_XOR_QUAD_CurrentVersionRun_c8fa {
  strings:
    $key_c8fa = { 9b 95 [2] bf 9b [2] 94 b7 [2] ba 95 [2] ae 8e [2] a1 94 [2] bf 89 [2] bd 88 [2] a6 8e [2] ba 89 [2] a6 a6 }

  condition:
    any of them
}