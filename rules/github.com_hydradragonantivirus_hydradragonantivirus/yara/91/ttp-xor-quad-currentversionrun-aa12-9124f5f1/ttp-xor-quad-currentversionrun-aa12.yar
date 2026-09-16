rule TTP_XOR_QUAD_CurrentVersionRun_aa12 {
  strings:
    $key_aa12 = { f9 7d [2] dd 73 [2] f6 5f [2] d8 7d [2] cc 66 [2] c3 7c [2] dd 61 [2] df 60 [2] c4 66 [2] d8 61 [2] c4 4e }

  condition:
    any of them
}