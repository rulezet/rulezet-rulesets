rule TTP_XOR_QUAD_CurrentVersionRun_bb29 {
  strings:
    $key_bb29 = { e8 46 [2] cc 48 [2] e7 64 [2] c9 46 [2] dd 5d [2] d2 47 [2] cc 5a [2] ce 5b [2] d5 5d [2] c9 5a [2] d5 75 }

  condition:
    any of them
}