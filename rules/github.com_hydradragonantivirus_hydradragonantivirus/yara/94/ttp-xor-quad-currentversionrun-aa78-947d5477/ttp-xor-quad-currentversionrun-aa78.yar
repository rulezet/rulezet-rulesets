rule TTP_XOR_QUAD_CurrentVersionRun_aa78 {
  strings:
    $key_aa78 = { f9 17 [2] dd 19 [2] f6 35 [2] d8 17 [2] cc 0c [2] c3 16 [2] dd 0b [2] df 0a [2] c4 0c [2] d8 0b [2] c4 24 }

  condition:
    any of them
}