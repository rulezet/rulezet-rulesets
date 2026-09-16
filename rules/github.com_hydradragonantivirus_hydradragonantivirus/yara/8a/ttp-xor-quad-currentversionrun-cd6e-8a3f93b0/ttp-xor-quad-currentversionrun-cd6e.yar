rule TTP_XOR_QUAD_CurrentVersionRun_cd6e {
  strings:
    $key_cd6e = { 9e 01 [2] ba 0f [2] 91 23 [2] bf 01 [2] ab 1a [2] a4 00 [2] ba 1d [2] b8 1c [2] a3 1a [2] bf 1d [2] a3 32 }

  condition:
    any of them
}