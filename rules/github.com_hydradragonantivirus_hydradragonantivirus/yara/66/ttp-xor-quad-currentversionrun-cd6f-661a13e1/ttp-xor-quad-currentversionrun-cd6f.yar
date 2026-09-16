rule TTP_XOR_QUAD_CurrentVersionRun_cd6f {
  strings:
    $key_cd6f = { 9e 00 [2] ba 0e [2] 91 22 [2] bf 00 [2] ab 1b [2] a4 01 [2] ba 1c [2] b8 1d [2] a3 1b [2] bf 1c [2] a3 33 }

  condition:
    any of them
}