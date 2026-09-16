rule TTP_XOR_QUAD_CurrentVersionRun_bb25 {
  strings:
    $key_bb25 = { e8 4a [2] cc 44 [2] e7 68 [2] c9 4a [2] dd 51 [2] d2 4b [2] cc 56 [2] ce 57 [2] d5 51 [2] c9 56 [2] d5 79 }

  condition:
    any of them
}