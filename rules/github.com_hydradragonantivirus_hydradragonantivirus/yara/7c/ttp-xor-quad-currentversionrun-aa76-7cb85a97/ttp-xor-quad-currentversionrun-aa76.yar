rule TTP_XOR_QUAD_CurrentVersionRun_aa76 {
  strings:
    $key_aa76 = { f9 19 [2] dd 17 [2] f6 3b [2] d8 19 [2] cc 02 [2] c3 18 [2] dd 05 [2] df 04 [2] c4 02 [2] d8 05 [2] c4 2a }

  condition:
    any of them
}