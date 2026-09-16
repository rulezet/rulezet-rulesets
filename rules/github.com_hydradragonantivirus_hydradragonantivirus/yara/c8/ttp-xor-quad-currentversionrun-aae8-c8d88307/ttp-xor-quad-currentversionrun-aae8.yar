rule TTP_XOR_QUAD_CurrentVersionRun_aae8 {
  strings:
    $key_aae8 = { f9 87 [2] dd 89 [2] f6 a5 [2] d8 87 [2] cc 9c [2] c3 86 [2] dd 9b [2] df 9a [2] c4 9c [2] d8 9b [2] c4 b4 }

  condition:
    any of them
}