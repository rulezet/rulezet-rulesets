rule TTP_XOR_QUAD_CurrentVersionRun_aaf4 {
  strings:
    $key_aaf4 = { f9 9b [2] dd 95 [2] f6 b9 [2] d8 9b [2] cc 80 [2] c3 9a [2] dd 87 [2] df 86 [2] c4 80 [2] d8 87 [2] c4 a8 }

  condition:
    any of them
}