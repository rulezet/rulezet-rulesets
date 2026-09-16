rule TTP_XOR_QUAD_CurrentVersionRun_c838 {
  strings:
    $key_c838 = { 9b 57 [2] bf 59 [2] 94 75 [2] ba 57 [2] ae 4c [2] a1 56 [2] bf 4b [2] bd 4a [2] a6 4c [2] ba 4b [2] a6 64 }

  condition:
    any of them
}