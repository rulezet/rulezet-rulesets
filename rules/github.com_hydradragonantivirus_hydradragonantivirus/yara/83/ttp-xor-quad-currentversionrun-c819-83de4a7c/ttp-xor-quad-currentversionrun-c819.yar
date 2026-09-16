rule TTP_XOR_QUAD_CurrentVersionRun_c819 {
  strings:
    $key_c819 = { 9b 76 [2] bf 78 [2] 94 54 [2] ba 76 [2] ae 6d [2] a1 77 [2] bf 6a [2] bd 6b [2] a6 6d [2] ba 6a [2] a6 45 }

  condition:
    any of them
}