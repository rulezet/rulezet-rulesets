rule TTP_XOR_QUAD_CurrentVersionRun_bb3a {
  strings:
    $key_bb3a = { e8 55 [2] cc 5b [2] e7 77 [2] c9 55 [2] dd 4e [2] d2 54 [2] cc 49 [2] ce 48 [2] d5 4e [2] c9 49 [2] d5 66 }

  condition:
    any of them
}