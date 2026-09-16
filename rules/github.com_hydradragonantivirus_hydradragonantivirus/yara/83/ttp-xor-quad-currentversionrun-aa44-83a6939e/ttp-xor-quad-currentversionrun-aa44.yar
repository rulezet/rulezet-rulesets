rule TTP_XOR_QUAD_CurrentVersionRun_aa44 {
  strings:
    $key_aa44 = { f9 2b [2] dd 25 [2] f6 09 [2] d8 2b [2] cc 30 [2] c3 2a [2] dd 37 [2] df 36 [2] c4 30 [2] d8 37 [2] c4 18 }

  condition:
    any of them
}