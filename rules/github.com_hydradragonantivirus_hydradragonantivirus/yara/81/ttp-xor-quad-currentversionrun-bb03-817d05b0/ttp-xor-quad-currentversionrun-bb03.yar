rule TTP_XOR_QUAD_CurrentVersionRun_bb03 {
  strings:
    $key_bb03 = { e8 6c [2] cc 62 [2] e7 4e [2] c9 6c [2] dd 77 [2] d2 6d [2] cc 70 [2] ce 71 [2] d5 77 [2] c9 70 [2] d5 5f }

  condition:
    any of them
}