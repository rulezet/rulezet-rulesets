rule TTP_XOR_QUAD_CurrentVersionRun_c82f {
  strings:
    $key_c82f = { 9b 40 [2] bf 4e [2] 94 62 [2] ba 40 [2] ae 5b [2] a1 41 [2] bf 5c [2] bd 5d [2] a6 5b [2] ba 5c [2] a6 73 }

  condition:
    any of them
}