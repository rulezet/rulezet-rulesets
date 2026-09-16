rule TTP_XOR_QUAD_CurrentVersionRun_bb24 {
  strings:
    $key_bb24 = { e8 4b [2] cc 45 [2] e7 69 [2] c9 4b [2] dd 50 [2] d2 4a [2] cc 57 [2] ce 56 [2] d5 50 [2] c9 57 [2] d5 78 }

  condition:
    any of them
}