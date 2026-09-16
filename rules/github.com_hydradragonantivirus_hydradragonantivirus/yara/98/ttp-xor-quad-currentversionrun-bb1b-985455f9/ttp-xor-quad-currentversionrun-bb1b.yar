rule TTP_XOR_QUAD_CurrentVersionRun_bb1b {
  strings:
    $key_bb1b = { e8 74 [2] cc 7a [2] e7 56 [2] c9 74 [2] dd 6f [2] d2 75 [2] cc 68 [2] ce 69 [2] d5 6f [2] c9 68 [2] d5 47 }

  condition:
    any of them
}