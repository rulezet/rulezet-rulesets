rule TTP_XOR_QUAD_CurrentVersionRun_d15f {
  strings:
    $key_d15f = { 82 30 [2] a6 3e [2] 8d 12 [2] a3 30 [2] b7 2b [2] b8 31 [2] a6 2c [2] a4 2d [2] bf 2b [2] a3 2c [2] bf 03 }

  condition:
    any of them
}