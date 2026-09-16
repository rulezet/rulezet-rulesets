rule TTP_XOR_QUAD_CurrentVersionRun_aa07 {
  strings:
    $key_aa07 = { f9 68 [2] dd 66 [2] f6 4a [2] d8 68 [2] cc 73 [2] c3 69 [2] dd 74 [2] df 75 [2] c4 73 [2] d8 74 [2] c4 5b }

  condition:
    any of them
}