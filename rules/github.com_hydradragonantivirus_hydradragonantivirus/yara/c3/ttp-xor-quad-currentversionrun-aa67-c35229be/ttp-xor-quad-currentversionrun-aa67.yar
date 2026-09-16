rule TTP_XOR_QUAD_CurrentVersionRun_aa67 {
  strings:
    $key_aa67 = { f9 08 [2] dd 06 [2] f6 2a [2] d8 08 [2] cc 13 [2] c3 09 [2] dd 14 [2] df 15 [2] c4 13 [2] d8 14 [2] c4 3b }

  condition:
    any of them
}