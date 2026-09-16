rule TTP_XOR_QUAD_CurrentVersionRun_cd5e {
  strings:
    $key_cd5e = { 9e 31 [2] ba 3f [2] 91 13 [2] bf 31 [2] ab 2a [2] a4 30 [2] ba 2d [2] b8 2c [2] a3 2a [2] bf 2d [2] a3 02 }

  condition:
    any of them
}