rule TTP_XOR_QUAD_CurrentVersionRun_bb5c {
  strings:
    $key_bb5c = { e8 33 [2] cc 3d [2] e7 11 [2] c9 33 [2] dd 28 [2] d2 32 [2] cc 2f [2] ce 2e [2] d5 28 [2] c9 2f [2] d5 00 }

  condition:
    any of them
}