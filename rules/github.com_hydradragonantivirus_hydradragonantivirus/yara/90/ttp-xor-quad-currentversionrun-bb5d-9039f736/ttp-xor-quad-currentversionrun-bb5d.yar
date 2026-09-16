rule TTP_XOR_QUAD_CurrentVersionRun_bb5d {
  strings:
    $key_bb5d = { e8 32 [2] cc 3c [2] e7 10 [2] c9 32 [2] dd 29 [2] d2 33 [2] cc 2e [2] ce 2f [2] d5 29 [2] c9 2e [2] d5 01 }

  condition:
    any of them
}