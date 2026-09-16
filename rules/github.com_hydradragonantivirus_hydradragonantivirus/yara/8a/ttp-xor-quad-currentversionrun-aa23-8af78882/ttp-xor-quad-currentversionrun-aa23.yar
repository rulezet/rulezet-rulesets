rule TTP_XOR_QUAD_CurrentVersionRun_aa23 {
  strings:
    $key_aa23 = { f9 4c [2] dd 42 [2] f6 6e [2] d8 4c [2] cc 57 [2] c3 4d [2] dd 50 [2] df 51 [2] c4 57 [2] d8 50 [2] c4 7f }

  condition:
    any of them
}