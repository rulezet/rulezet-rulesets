rule TTP_XOR_QUAD_CurrentVersionRun_bbfb {
  strings:
    $key_bbfb = { e8 94 [2] cc 9a [2] e7 b6 [2] c9 94 [2] dd 8f [2] d2 95 [2] cc 88 [2] ce 89 [2] d5 8f [2] c9 88 [2] d5 a7 }

  condition:
    any of them
}