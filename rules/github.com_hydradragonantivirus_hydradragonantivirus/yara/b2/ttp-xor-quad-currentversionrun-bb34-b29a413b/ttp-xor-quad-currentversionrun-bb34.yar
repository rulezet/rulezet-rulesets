rule TTP_XOR_QUAD_CurrentVersionRun_bb34 {
  strings:
    $key_bb34 = { e8 5b [2] cc 55 [2] e7 79 [2] c9 5b [2] dd 40 [2] d2 5a [2] cc 47 [2] ce 46 [2] d5 40 [2] c9 47 [2] d5 68 }

  condition:
    any of them
}