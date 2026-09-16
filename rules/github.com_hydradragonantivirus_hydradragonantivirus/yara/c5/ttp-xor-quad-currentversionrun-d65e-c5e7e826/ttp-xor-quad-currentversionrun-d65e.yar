rule TTP_XOR_QUAD_CurrentVersionRun_d65e {
  strings:
    $key_d65e = { 85 31 [2] a1 3f [2] 8a 13 [2] a4 31 [2] b0 2a [2] bf 30 [2] a1 2d [2] a3 2c [2] b8 2a [2] a4 2d [2] b8 02 }

  condition:
    any of them
}