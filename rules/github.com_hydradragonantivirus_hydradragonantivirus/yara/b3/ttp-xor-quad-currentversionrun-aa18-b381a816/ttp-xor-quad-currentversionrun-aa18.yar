rule TTP_XOR_QUAD_CurrentVersionRun_aa18 {
  strings:
    $key_aa18 = { f9 77 [2] dd 79 [2] f6 55 [2] d8 77 [2] cc 6c [2] c3 76 [2] dd 6b [2] df 6a [2] c4 6c [2] d8 6b [2] c4 44 }

  condition:
    any of them
}