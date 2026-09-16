rule TTP_XOR_QUAD_CurrentVersionRun_c65e {
  strings:
    $key_c65e = { 95 31 [2] b1 3f [2] 9a 13 [2] b4 31 [2] a0 2a [2] af 30 [2] b1 2d [2] b3 2c [2] a8 2a [2] b4 2d [2] a8 02 }

  condition:
    any of them
}