rule TTP_XOR_QUAD_CurrentVersionRun_aa53 {
  strings:
    $key_aa53 = { f9 3c [2] dd 32 [2] f6 1e [2] d8 3c [2] cc 27 [2] c3 3d [2] dd 20 [2] df 21 [2] c4 27 [2] d8 20 [2] c4 0f }

  condition:
    any of them
}