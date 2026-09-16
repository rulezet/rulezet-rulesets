rule TTP_XOR_QUAD_CurrentVersionRun_c81f {
  strings:
    $key_c81f = { 9b 70 [2] bf 7e [2] 94 52 [2] ba 70 [2] ae 6b [2] a1 71 [2] bf 6c [2] bd 6d [2] a6 6b [2] ba 6c [2] a6 43 }

  condition:
    any of them
}