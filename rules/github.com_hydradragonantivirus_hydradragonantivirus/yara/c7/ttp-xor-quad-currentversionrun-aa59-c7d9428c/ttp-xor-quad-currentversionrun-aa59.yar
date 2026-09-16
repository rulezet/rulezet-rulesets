rule TTP_XOR_QUAD_CurrentVersionRun_aa59 {
  strings:
    $key_aa59 = { f9 36 [2] dd 38 [2] f6 14 [2] d8 36 [2] cc 2d [2] c3 37 [2] dd 2a [2] df 2b [2] c4 2d [2] d8 2a [2] c4 05 }

  condition:
    any of them
}