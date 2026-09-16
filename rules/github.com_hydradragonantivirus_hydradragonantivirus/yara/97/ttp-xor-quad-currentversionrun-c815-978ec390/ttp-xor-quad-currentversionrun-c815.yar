rule TTP_XOR_QUAD_CurrentVersionRun_c815 {
  strings:
    $key_c815 = { 9b 7a [2] bf 74 [2] 94 58 [2] ba 7a [2] ae 61 [2] a1 7b [2] bf 66 [2] bd 67 [2] a6 61 [2] ba 66 [2] a6 49 }

  condition:
    any of them
}