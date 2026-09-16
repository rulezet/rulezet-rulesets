rule TTP_XOR_QUAD_CurrentVersionRun_c8ff {
  strings:
    $key_c8ff = { 9b 90 [2] bf 9e [2] 94 b2 [2] ba 90 [2] ae 8b [2] a1 91 [2] bf 8c [2] bd 8d [2] a6 8b [2] ba 8c [2] a6 a3 }

  condition:
    any of them
}