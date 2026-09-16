rule TTP_XOR_QUAD_CurrentVersionRun_c845 {
  strings:
    $key_c845 = { 9b 2a [2] bf 24 [2] 94 08 [2] ba 2a [2] ae 31 [2] a1 2b [2] bf 36 [2] bd 37 [2] a6 31 [2] ba 36 [2] a6 19 }

  condition:
    any of them
}