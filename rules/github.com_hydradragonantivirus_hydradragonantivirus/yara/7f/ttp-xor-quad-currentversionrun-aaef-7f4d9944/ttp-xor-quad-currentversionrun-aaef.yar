rule TTP_XOR_QUAD_CurrentVersionRun_aaef {
  strings:
    $key_aaef = { f9 80 [2] dd 8e [2] f6 a2 [2] d8 80 [2] cc 9b [2] c3 81 [2] dd 9c [2] df 9d [2] c4 9b [2] d8 9c [2] c4 b3 }

  condition:
    any of them
}