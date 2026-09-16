rule TTP_XOR_QUAD_CurrentVersionRun_bb09 {
  strings:
    $key_bb09 = { e8 66 [2] cc 68 [2] e7 44 [2] c9 66 [2] dd 7d [2] d2 67 [2] cc 7a [2] ce 7b [2] d5 7d [2] c9 7a [2] d5 55 }

  condition:
    any of them
}