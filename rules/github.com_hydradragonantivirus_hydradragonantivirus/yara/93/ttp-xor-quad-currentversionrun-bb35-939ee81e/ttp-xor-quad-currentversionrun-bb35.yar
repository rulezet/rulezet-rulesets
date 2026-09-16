rule TTP_XOR_QUAD_CurrentVersionRun_bb35 {
  strings:
    $key_bb35 = { e8 5a [2] cc 54 [2] e7 78 [2] c9 5a [2] dd 41 [2] d2 5b [2] cc 46 [2] ce 47 [2] d5 41 [2] c9 46 [2] d5 69 }

  condition:
    any of them
}