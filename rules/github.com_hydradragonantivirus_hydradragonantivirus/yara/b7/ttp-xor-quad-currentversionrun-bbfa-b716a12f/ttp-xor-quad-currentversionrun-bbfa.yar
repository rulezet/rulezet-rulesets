rule TTP_XOR_QUAD_CurrentVersionRun_bbfa {
  strings:
    $key_bbfa = { e8 95 [2] cc 9b [2] e7 b7 [2] c9 95 [2] dd 8e [2] d2 94 [2] cc 89 [2] ce 88 [2] d5 8e [2] c9 89 [2] d5 a6 }

  condition:
    any of them
}