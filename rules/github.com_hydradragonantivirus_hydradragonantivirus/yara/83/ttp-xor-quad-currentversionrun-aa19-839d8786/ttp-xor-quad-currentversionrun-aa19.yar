rule TTP_XOR_QUAD_CurrentVersionRun_aa19 {
  strings:
    $key_aa19 = { f9 76 [2] dd 78 [2] f6 54 [2] d8 76 [2] cc 6d [2] c3 77 [2] dd 6a [2] df 6b [2] c4 6d [2] d8 6a [2] c4 45 }

  condition:
    any of them
}