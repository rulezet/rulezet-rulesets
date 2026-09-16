rule TTP_XOR_QUAD_CurrentVersionRun_c75e {
  strings:
    $key_c75e = { 94 31 [2] b0 3f [2] 9b 13 [2] b5 31 [2] a1 2a [2] ae 30 [2] b0 2d [2] b2 2c [2] a9 2a [2] b5 2d [2] a9 02 }

  condition:
    any of them
}