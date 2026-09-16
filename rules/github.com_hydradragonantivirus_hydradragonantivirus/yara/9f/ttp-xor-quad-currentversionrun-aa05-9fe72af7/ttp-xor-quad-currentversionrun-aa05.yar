rule TTP_XOR_QUAD_CurrentVersionRun_aa05 {
  strings:
    $key_aa05 = { f9 6a [2] dd 64 [2] f6 48 [2] d8 6a [2] cc 71 [2] c3 6b [2] dd 76 [2] df 77 [2] c4 71 [2] d8 76 [2] c4 59 }

  condition:
    any of them
}