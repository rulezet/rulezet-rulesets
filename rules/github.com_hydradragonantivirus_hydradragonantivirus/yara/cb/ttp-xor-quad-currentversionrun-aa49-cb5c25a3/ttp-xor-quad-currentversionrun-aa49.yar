rule TTP_XOR_QUAD_CurrentVersionRun_aa49 {
  strings:
    $key_aa49 = { f9 26 [2] dd 28 [2] f6 04 [2] d8 26 [2] cc 3d [2] c3 27 [2] dd 3a [2] df 3b [2] c4 3d [2] d8 3a [2] c4 15 }

  condition:
    any of them
}