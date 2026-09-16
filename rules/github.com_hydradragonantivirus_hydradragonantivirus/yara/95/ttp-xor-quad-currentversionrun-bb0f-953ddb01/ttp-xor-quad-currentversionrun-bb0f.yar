rule TTP_XOR_QUAD_CurrentVersionRun_bb0f {
  strings:
    $key_bb0f = { e8 60 [2] cc 6e [2] e7 42 [2] c9 60 [2] dd 7b [2] d2 61 [2] cc 7c [2] ce 7d [2] d5 7b [2] c9 7c [2] d5 53 }

  condition:
    any of them
}