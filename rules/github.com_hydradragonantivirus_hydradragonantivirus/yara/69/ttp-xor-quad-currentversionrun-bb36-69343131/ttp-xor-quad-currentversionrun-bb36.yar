rule TTP_XOR_QUAD_CurrentVersionRun_bb36 {
  strings:
    $key_bb36 = { e8 59 [2] cc 57 [2] e7 7b [2] c9 59 [2] dd 42 [2] d2 58 [2] cc 45 [2] ce 44 [2] d5 42 [2] c9 45 [2] d5 6a }

  condition:
    any of them
}