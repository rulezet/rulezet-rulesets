rule TTP_XOR_QUAD_CurrentVersionRun_c857 {
  strings:
    $key_c857 = { 9b 38 [2] bf 36 [2] 94 1a [2] ba 38 [2] ae 23 [2] a1 39 [2] bf 24 [2] bd 25 [2] a6 23 [2] ba 24 [2] a6 0b }

  condition:
    any of them
}