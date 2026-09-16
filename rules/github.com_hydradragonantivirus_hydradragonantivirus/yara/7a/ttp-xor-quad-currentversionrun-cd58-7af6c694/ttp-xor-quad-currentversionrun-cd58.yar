rule TTP_XOR_QUAD_CurrentVersionRun_cd58 {
  strings:
    $key_cd58 = { 9e 37 [2] ba 39 [2] 91 15 [2] bf 37 [2] ab 2c [2] a4 36 [2] ba 2b [2] b8 2a [2] a3 2c [2] bf 2b [2] a3 04 }

  condition:
    any of them
}