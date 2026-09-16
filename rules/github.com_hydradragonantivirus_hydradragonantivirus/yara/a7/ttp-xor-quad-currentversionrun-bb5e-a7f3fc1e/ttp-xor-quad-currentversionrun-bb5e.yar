rule TTP_XOR_QUAD_CurrentVersionRun_bb5e {
  strings:
    $key_bb5e = { e8 31 [2] cc 3f [2] e7 13 [2] c9 31 [2] dd 2a [2] d2 30 [2] cc 2d [2] ce 2c [2] d5 2a [2] c9 2d [2] d5 02 }

  condition:
    any of them
}