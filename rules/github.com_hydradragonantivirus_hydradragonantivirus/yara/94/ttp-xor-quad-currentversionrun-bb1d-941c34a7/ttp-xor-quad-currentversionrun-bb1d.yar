rule TTP_XOR_QUAD_CurrentVersionRun_bb1d {
  strings:
    $key_bb1d = { e8 72 [2] cc 7c [2] e7 50 [2] c9 72 [2] dd 69 [2] d2 73 [2] cc 6e [2] ce 6f [2] d5 69 [2] c9 6e [2] d5 41 }

  condition:
    any of them
}