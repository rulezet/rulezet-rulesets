rule TTP_XOR_QUAD_CurrentVersionRun_bb15 {
  strings:
    $key_bb15 = { e8 7a [2] cc 74 [2] e7 58 [2] c9 7a [2] dd 61 [2] d2 7b [2] cc 66 [2] ce 67 [2] d5 61 [2] c9 66 [2] d5 49 }

  condition:
    any of them
}