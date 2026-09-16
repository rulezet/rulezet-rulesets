rule TTP_XOR_QUAD_CurrentVersionRun_bb57 {
  strings:
    $key_bb57 = { e8 38 [2] cc 36 [2] e7 1a [2] c9 38 [2] dd 23 [2] d2 39 [2] cc 24 [2] ce 25 [2] d5 23 [2] c9 24 [2] d5 0b }

  condition:
    any of them
}