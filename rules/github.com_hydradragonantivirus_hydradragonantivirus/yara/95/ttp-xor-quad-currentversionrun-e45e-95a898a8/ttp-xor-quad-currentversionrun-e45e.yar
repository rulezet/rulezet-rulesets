rule TTP_XOR_QUAD_CurrentVersionRun_e45e {
  strings:
    $key_e45e = { b7 31 [2] 93 3f [2] b8 13 [2] 96 31 [2] 82 2a [2] 8d 30 [2] 93 2d [2] 91 2c [2] 8a 2a [2] 96 2d [2] 8a 02 }

  condition:
    any of them
}