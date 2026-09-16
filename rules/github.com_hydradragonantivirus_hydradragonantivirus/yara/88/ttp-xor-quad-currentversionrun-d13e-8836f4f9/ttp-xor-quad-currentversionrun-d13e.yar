rule TTP_XOR_QUAD_CurrentVersionRun_d13e {
  strings:
    $key_d13e = { 82 51 [2] a6 5f [2] 8d 73 [2] a3 51 [2] b7 4a [2] b8 50 [2] a6 4d [2] a4 4c [2] bf 4a [2] a3 4d [2] bf 62 }

  condition:
    any of them
}