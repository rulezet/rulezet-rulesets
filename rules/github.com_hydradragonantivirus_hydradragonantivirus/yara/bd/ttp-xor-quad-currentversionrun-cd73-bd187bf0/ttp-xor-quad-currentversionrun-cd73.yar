rule TTP_XOR_QUAD_CurrentVersionRun_cd73 {
  strings:
    $key_cd73 = { 9e 1c [2] ba 12 [2] 91 3e [2] bf 1c [2] ab 07 [2] a4 1d [2] ba 00 [2] b8 01 [2] a3 07 [2] bf 00 [2] a3 2f }

  condition:
    any of them
}