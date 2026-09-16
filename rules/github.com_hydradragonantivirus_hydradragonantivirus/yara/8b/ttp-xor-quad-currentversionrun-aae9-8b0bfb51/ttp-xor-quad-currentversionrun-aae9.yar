rule TTP_XOR_QUAD_CurrentVersionRun_aae9 {
  strings:
    $key_aae9 = { f9 86 [2] dd 88 [2] f6 a4 [2] d8 86 [2] cc 9d [2] c3 87 [2] dd 9a [2] df 9b [2] c4 9d [2] d8 9a [2] c4 b5 }

  condition:
    any of them
}