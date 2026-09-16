rule TTP_XOR_QUAD_CurrentVersionRun_bb0b {
  strings:
    $key_bb0b = { e8 64 [2] cc 6a [2] e7 46 [2] c9 64 [2] dd 7f [2] d2 65 [2] cc 78 [2] ce 79 [2] d5 7f [2] c9 78 [2] d5 57 }

  condition:
    any of them
}