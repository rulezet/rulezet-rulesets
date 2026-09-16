rule TTP_XOR_QUAD_CurrentVersionRun_bb45 {
  strings:
    $key_bb45 = { e8 2a [2] cc 24 [2] e7 08 [2] c9 2a [2] dd 31 [2] d2 2b [2] cc 36 [2] ce 37 [2] d5 31 [2] c9 36 [2] d5 19 }

  condition:
    any of them
}