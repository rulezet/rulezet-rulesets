rule TTP_XOR_QUAD_CurrentVersionRun_c8e2 {
  strings:
    $key_c8e2 = { 9b 8d [2] bf 83 [2] 94 af [2] ba 8d [2] ae 96 [2] a1 8c [2] bf 91 [2] bd 90 [2] a6 96 [2] ba 91 [2] a6 be }

  condition:
    any of them
}