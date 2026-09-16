rule TTP_XOR_QUAD_CurrentVersionRun_bb2d {
  strings:
    $key_bb2d = { e8 42 [2] cc 4c [2] e7 60 [2] c9 42 [2] dd 59 [2] d2 43 [2] cc 5e [2] ce 5f [2] d5 59 [2] c9 5e [2] d5 71 }

  condition:
    any of them
}