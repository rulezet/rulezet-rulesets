rule TTP_XOR_QUAD_CurrentVersionRun_c847 {
  strings:
    $key_c847 = { 9b 28 [2] bf 26 [2] 94 0a [2] ba 28 [2] ae 33 [2] a1 29 [2] bf 34 [2] bd 35 [2] a6 33 [2] ba 34 [2] a6 1b }

  condition:
    any of them
}