rule TTP_XOR_QUAD_CurrentVersionRun_aa08 {
  strings:
    $key_aa08 = { f9 67 [2] dd 69 [2] f6 45 [2] d8 67 [2] cc 7c [2] c3 66 [2] dd 7b [2] df 7a [2] c4 7c [2] d8 7b [2] c4 54 }

  condition:
    any of them
}