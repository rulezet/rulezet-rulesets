rule TTP_XOR_QUAD_CurrentVersionRun_bb4a {
  strings:
    $key_bb4a = { e8 25 [2] cc 2b [2] e7 07 [2] c9 25 [2] dd 3e [2] d2 24 [2] cc 39 [2] ce 38 [2] d5 3e [2] c9 39 [2] d5 16 }

  condition:
    any of them
}