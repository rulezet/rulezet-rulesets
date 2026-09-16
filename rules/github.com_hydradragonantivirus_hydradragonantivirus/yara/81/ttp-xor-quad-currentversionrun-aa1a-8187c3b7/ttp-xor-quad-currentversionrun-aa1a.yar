rule TTP_XOR_QUAD_CurrentVersionRun_aa1a {
  strings:
    $key_aa1a = { f9 75 [2] dd 7b [2] f6 57 [2] d8 75 [2] cc 6e [2] c3 74 [2] dd 69 [2] df 68 [2] c4 6e [2] d8 69 [2] c4 46 }

  condition:
    any of them
}