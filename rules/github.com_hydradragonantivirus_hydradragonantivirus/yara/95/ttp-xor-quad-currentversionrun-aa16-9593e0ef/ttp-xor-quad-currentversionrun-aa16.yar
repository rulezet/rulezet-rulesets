rule TTP_XOR_QUAD_CurrentVersionRun_aa16 {
  strings:
    $key_aa16 = { f9 79 [2] dd 77 [2] f6 5b [2] d8 79 [2] cc 62 [2] c3 78 [2] dd 65 [2] df 64 [2] c4 62 [2] d8 65 [2] c4 4a }

  condition:
    any of them
}