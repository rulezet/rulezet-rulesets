rule TTP_XOR_QUAD_CurrentVersionRun_cd63 {
  strings:
    $key_cd63 = { 9e 0c [2] ba 02 [2] 91 2e [2] bf 0c [2] ab 17 [2] a4 0d [2] ba 10 [2] b8 11 [2] a3 17 [2] bf 10 [2] a3 3f }

  condition:
    any of them
}