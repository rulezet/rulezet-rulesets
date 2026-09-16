rule TTP_XOR_QUAD_CurrentVersionRun_bb04 {
  strings:
    $key_bb04 = { e8 6b [2] cc 65 [2] e7 49 [2] c9 6b [2] dd 70 [2] d2 6a [2] cc 77 [2] ce 76 [2] d5 70 [2] c9 77 [2] d5 58 }

  condition:
    any of them
}