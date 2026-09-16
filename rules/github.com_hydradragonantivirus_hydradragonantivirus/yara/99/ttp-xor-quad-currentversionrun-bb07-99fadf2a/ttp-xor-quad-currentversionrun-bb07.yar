rule TTP_XOR_QUAD_CurrentVersionRun_bb07 {
  strings:
    $key_bb07 = { e8 68 [2] cc 66 [2] e7 4a [2] c9 68 [2] dd 73 [2] d2 69 [2] cc 74 [2] ce 75 [2] d5 73 [2] c9 74 [2] d5 5b }

  condition:
    any of them
}