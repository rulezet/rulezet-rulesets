rule TTP_XOR_QUAD_CurrentVersionRun_bbeb {
  strings:
    $key_bbeb = { e8 84 [2] cc 8a [2] e7 a6 [2] c9 84 [2] dd 9f [2] d2 85 [2] cc 98 [2] ce 99 [2] d5 9f [2] c9 98 [2] d5 b7 }

  condition:
    any of them
}