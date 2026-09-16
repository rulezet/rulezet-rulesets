rule TTP_XOR_QUAD_CurrentVersionRun_aa55 {
  strings:
    $key_aa55 = { f9 3a [2] dd 34 [2] f6 18 [2] d8 3a [2] cc 21 [2] c3 3b [2] dd 26 [2] df 27 [2] c4 21 [2] d8 26 [2] c4 09 }

  condition:
    any of them
}