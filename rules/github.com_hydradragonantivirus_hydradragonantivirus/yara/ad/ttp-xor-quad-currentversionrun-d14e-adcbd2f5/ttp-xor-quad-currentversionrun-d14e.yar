rule TTP_XOR_QUAD_CurrentVersionRun_d14e {
  strings:
    $key_d14e = { 82 21 [2] a6 2f [2] 8d 03 [2] a3 21 [2] b7 3a [2] b8 20 [2] a6 3d [2] a4 3c [2] bf 3a [2] a3 3d [2] bf 12 }

  condition:
    any of them
}