rule TTP_XOR_QUAD_CurrentVersionRun_bb16 {
  strings:
    $key_bb16 = { e8 79 [2] cc 77 [2] e7 5b [2] c9 79 [2] dd 62 [2] d2 78 [2] cc 65 [2] ce 64 [2] d5 62 [2] c9 65 [2] d5 4a }

  condition:
    any of them
}