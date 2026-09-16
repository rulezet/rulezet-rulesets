rule TTP_XOR_QUAD_CurrentVersionRun_bbfc {
  strings:
    $key_bbfc = { e8 93 [2] cc 9d [2] e7 b1 [2] c9 93 [2] dd 88 [2] d2 92 [2] cc 8f [2] ce 8e [2] d5 88 [2] c9 8f [2] d5 a0 }

  condition:
    any of them
}