rule TTP_XOR_QUAD_CurrentVersionRun_c858 {
  strings:
    $key_c858 = { 9b 37 [2] bf 39 [2] 94 15 [2] ba 37 [2] ae 2c [2] a1 36 [2] bf 2b [2] bd 2a [2] a6 2c [2] ba 2b [2] a6 04 }

  condition:
    any of them
}