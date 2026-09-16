rule TTP_XOR_QUAD_CurrentVersionRun_aa54 {
  strings:
    $key_aa54 = { f9 3b [2] dd 35 [2] f6 19 [2] d8 3b [2] cc 20 [2] c3 3a [2] dd 27 [2] df 26 [2] c4 20 [2] d8 27 [2] c4 08 }

  condition:
    any of them
}