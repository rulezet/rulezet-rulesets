rule TTP_XOR_QUAD_CurrentVersionRun_aae5 {
  strings:
    $key_aae5 = { f9 8a [2] dd 84 [2] f6 a8 [2] d8 8a [2] cc 91 [2] c3 8b [2] dd 96 [2] df 97 [2] c4 91 [2] d8 96 [2] c4 b9 }

  condition:
    any of them
}