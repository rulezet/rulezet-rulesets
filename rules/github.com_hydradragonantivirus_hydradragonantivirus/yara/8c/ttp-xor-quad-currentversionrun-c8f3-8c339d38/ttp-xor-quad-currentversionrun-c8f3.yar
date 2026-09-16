rule TTP_XOR_QUAD_CurrentVersionRun_c8f3 {
  strings:
    $key_c8f3 = { 9b 9c [2] bf 92 [2] 94 be [2] ba 9c [2] ae 87 [2] a1 9d [2] bf 80 [2] bd 81 [2] a6 87 [2] ba 80 [2] a6 af }

  condition:
    any of them
}