rule TTP_XOR_QUAD_CurrentVersionRun_c85d {
  strings:
    $key_c85d = { 9b 32 [2] bf 3c [2] 94 10 [2] ba 32 [2] ae 29 [2] a1 33 [2] bf 2e [2] bd 2f [2] a6 29 [2] ba 2e [2] a6 01 }

  condition:
    any of them
}