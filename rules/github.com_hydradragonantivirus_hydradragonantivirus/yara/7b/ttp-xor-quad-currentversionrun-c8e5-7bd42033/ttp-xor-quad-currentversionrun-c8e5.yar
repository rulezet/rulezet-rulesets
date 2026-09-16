rule TTP_XOR_QUAD_CurrentVersionRun_c8e5 {
  strings:
    $key_c8e5 = { 9b 8a [2] bf 84 [2] 94 a8 [2] ba 8a [2] ae 91 [2] a1 8b [2] bf 96 [2] bd 97 [2] a6 91 [2] ba 96 [2] a6 b9 }

  condition:
    any of them
}