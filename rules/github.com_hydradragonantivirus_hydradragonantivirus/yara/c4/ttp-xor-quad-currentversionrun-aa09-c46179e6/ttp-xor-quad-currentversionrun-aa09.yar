rule TTP_XOR_QUAD_CurrentVersionRun_aa09 {
  strings:
    $key_aa09 = { f9 66 [2] dd 68 [2] f6 44 [2] d8 66 [2] cc 7d [2] c3 67 [2] dd 7a [2] df 7b [2] c4 7d [2] d8 7a [2] c4 55 }

  condition:
    any of them
}