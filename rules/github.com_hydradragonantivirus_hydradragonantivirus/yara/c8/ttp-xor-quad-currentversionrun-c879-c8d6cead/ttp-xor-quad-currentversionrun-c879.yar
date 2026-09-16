rule TTP_XOR_QUAD_CurrentVersionRun_c879 {
  strings:
    $key_c879 = { 9b 16 [2] bf 18 [2] 94 34 [2] ba 16 [2] ae 0d [2] a1 17 [2] bf 0a [2] bd 0b [2] a6 0d [2] ba 0a [2] a6 25 }

  condition:
    any of them
}