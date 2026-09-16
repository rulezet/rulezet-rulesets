rule TTP_XOR_QUAD_CurrentVersionRun_bb23 {
  strings:
    $key_bb23 = { e8 4c [2] cc 42 [2] e7 6e [2] c9 4c [2] dd 57 [2] d2 4d [2] cc 50 [2] ce 51 [2] d5 57 [2] c9 50 [2] d5 7f }

  condition:
    any of them
}