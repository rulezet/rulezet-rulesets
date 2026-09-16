rule TTP_XOR_QUAD_CurrentVersionRun_bb50 {
  strings:
    $key_bb50 = { e8 3f [2] cc 31 [2] e7 1d [2] c9 3f [2] dd 24 [2] d2 3e [2] cc 23 [2] ce 22 [2] d5 24 [2] c9 23 [2] d5 0c }

  condition:
    any of them
}