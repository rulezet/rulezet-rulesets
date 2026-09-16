rule TTP_XOR_QUAD_CurrentVersionRun_bb05 {
  strings:
    $key_bb05 = { e8 6a [2] cc 64 [2] e7 48 [2] c9 6a [2] dd 71 [2] d2 6b [2] cc 76 [2] ce 77 [2] d5 71 [2] c9 76 [2] d5 59 }

  condition:
    any of them
}