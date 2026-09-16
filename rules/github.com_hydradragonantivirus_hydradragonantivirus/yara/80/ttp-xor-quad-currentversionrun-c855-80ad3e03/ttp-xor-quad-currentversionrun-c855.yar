rule TTP_XOR_QUAD_CurrentVersionRun_c855 {
  strings:
    $key_c855 = { 9b 3a [2] bf 34 [2] 94 18 [2] ba 3a [2] ae 21 [2] a1 3b [2] bf 26 [2] bd 27 [2] a6 21 [2] ba 26 [2] a6 09 }

  condition:
    any of them
}