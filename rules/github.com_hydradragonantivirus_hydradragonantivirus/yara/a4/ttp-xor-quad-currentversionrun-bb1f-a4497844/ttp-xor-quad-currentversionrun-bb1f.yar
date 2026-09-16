rule TTP_XOR_QUAD_CurrentVersionRun_bb1f {
  strings:
    $key_bb1f = { e8 70 [2] cc 7e [2] e7 52 [2] c9 70 [2] dd 6b [2] d2 71 [2] cc 6c [2] ce 6d [2] d5 6b [2] c9 6c [2] d5 43 }

  condition:
    any of them
}