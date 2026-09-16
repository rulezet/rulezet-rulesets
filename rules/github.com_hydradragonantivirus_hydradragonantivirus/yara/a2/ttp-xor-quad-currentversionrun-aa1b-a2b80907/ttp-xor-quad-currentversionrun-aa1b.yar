rule TTP_XOR_QUAD_CurrentVersionRun_aa1b {
  strings:
    $key_aa1b = { f9 74 [2] dd 7a [2] f6 56 [2] d8 74 [2] cc 6f [2] c3 75 [2] dd 68 [2] df 69 [2] c4 6f [2] d8 68 [2] c4 47 }

  condition:
    any of them
}