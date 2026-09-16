rule TTP_XOR_QUAD_CurrentVersionRun_d16f {
  strings:
    $key_d16f = { 82 00 [2] a6 0e [2] 8d 22 [2] a3 00 [2] b7 1b [2] b8 01 [2] a6 1c [2] a4 1d [2] bf 1b [2] a3 1c [2] bf 33 }

  condition:
    any of them
}