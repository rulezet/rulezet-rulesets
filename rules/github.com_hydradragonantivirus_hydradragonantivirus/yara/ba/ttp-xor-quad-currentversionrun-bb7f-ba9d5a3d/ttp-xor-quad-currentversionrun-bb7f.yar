rule TTP_XOR_QUAD_CurrentVersionRun_bb7f {
  strings:
    $key_bb7f = { e8 10 [2] cc 1e [2] e7 32 [2] c9 10 [2] dd 0b [2] d2 11 [2] cc 0c [2] ce 0d [2] d5 0b [2] c9 0c [2] d5 23 }

  condition:
    any of them
}