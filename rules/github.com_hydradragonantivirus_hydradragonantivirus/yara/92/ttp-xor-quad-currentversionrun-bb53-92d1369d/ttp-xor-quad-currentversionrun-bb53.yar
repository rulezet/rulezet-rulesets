rule TTP_XOR_QUAD_CurrentVersionRun_bb53 {
  strings:
    $key_bb53 = { e8 3c [2] cc 32 [2] e7 1e [2] c9 3c [2] dd 27 [2] d2 3d [2] cc 20 [2] ce 21 [2] d5 27 [2] c9 20 [2] d5 0f }

  condition:
    any of them
}