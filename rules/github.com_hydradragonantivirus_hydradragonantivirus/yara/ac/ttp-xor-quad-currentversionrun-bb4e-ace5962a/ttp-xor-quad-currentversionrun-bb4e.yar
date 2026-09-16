rule TTP_XOR_QUAD_CurrentVersionRun_bb4e {
  strings:
    $key_bb4e = { e8 21 [2] cc 2f [2] e7 03 [2] c9 21 [2] dd 3a [2] d2 20 [2] cc 3d [2] ce 3c [2] d5 3a [2] c9 3d [2] d5 12 }

  condition:
    any of them
}