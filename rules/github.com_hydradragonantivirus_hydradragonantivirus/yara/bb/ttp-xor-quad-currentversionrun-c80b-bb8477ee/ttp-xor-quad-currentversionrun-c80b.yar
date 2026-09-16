rule TTP_XOR_QUAD_CurrentVersionRun_c80b {
  strings:
    $key_c80b = { 9b 64 [2] bf 6a [2] 94 46 [2] ba 64 [2] ae 7f [2] a1 65 [2] bf 78 [2] bd 79 [2] a6 7f [2] ba 78 [2] a6 57 }

  condition:
    any of them
}