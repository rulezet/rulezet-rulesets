rule TTP_XOR_QUAD_CurrentVersionRun_c8f9 {
  strings:
    $key_c8f9 = { 9b 96 [2] bf 98 [2] 94 b4 [2] ba 96 [2] ae 8d [2] a1 97 [2] bf 8a [2] bd 8b [2] a6 8d [2] ba 8a [2] a6 a5 }

  condition:
    any of them
}