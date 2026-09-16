rule TTP_XOR_QUAD_CurrentVersionRun_bb63 {
  strings:
    $key_bb63 = { e8 0c [2] cc 02 [2] e7 2e [2] c9 0c [2] dd 17 [2] d2 0d [2] cc 10 [2] ce 11 [2] d5 17 [2] c9 10 [2] d5 3f }

  condition:
    any of them
}