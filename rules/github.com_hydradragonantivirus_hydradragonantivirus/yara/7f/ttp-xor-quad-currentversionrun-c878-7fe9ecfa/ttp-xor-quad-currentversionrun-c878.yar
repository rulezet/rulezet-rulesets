rule TTP_XOR_QUAD_CurrentVersionRun_c878 {
  strings:
    $key_c878 = { 9b 17 [2] bf 19 [2] 94 35 [2] ba 17 [2] ae 0c [2] a1 16 [2] bf 0b [2] bd 0a [2] a6 0c [2] ba 0b [2] a6 24 }

  condition:
    any of them
}