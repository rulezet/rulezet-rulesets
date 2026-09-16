rule TTP_XOR_QUAD_CurrentVersionRun_cd43 {
  strings:
    $key_cd43 = { 9e 2c [2] ba 22 [2] 91 0e [2] bf 2c [2] ab 37 [2] a4 2d [2] ba 30 [2] b8 31 [2] a3 37 [2] bf 30 [2] a3 1f }

  condition:
    any of them
}