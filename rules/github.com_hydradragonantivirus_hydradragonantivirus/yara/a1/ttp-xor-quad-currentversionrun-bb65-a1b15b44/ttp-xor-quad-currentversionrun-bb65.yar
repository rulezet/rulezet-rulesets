rule TTP_XOR_QUAD_CurrentVersionRun_bb65 {
  strings:
    $key_bb65 = { e8 0a [2] cc 04 [2] e7 28 [2] c9 0a [2] dd 11 [2] d2 0b [2] cc 16 [2] ce 17 [2] d5 11 [2] c9 16 [2] d5 39 }

  condition:
    any of them
}