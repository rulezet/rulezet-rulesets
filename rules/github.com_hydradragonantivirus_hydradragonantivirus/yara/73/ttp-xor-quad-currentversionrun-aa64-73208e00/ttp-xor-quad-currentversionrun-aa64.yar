rule TTP_XOR_QUAD_CurrentVersionRun_aa64 {
  strings:
    $key_aa64 = { f9 0b [2] dd 05 [2] f6 29 [2] d8 0b [2] cc 10 [2] c3 0a [2] dd 17 [2] df 16 [2] c4 10 [2] d8 17 [2] c4 38 }

  condition:
    any of them
}