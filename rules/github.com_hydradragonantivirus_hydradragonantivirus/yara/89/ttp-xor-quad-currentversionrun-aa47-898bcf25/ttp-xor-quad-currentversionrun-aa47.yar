rule TTP_XOR_QUAD_CurrentVersionRun_aa47 {
  strings:
    $key_aa47 = { f9 28 [2] dd 26 [2] f6 0a [2] d8 28 [2] cc 33 [2] c3 29 [2] dd 34 [2] df 35 [2] c4 33 [2] d8 34 [2] c4 1b }

  condition:
    any of them
}