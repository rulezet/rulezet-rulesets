rule TTP_XOR_QUAD_CurrentVersionRun_aa45 {
  strings:
    $key_aa45 = { f9 2a [2] dd 24 [2] f6 08 [2] d8 2a [2] cc 31 [2] c3 2b [2] dd 36 [2] df 37 [2] c4 31 [2] d8 36 [2] c4 19 }

  condition:
    any of them
}