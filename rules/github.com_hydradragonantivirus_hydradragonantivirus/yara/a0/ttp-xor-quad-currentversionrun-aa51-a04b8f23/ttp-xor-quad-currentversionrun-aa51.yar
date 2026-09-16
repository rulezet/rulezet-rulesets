rule TTP_XOR_QUAD_CurrentVersionRun_aa51 {
  strings:
    $key_aa51 = { f9 3e [2] dd 30 [2] f6 1c [2] d8 3e [2] cc 25 [2] c3 3f [2] dd 22 [2] df 23 [2] c4 25 [2] d8 22 [2] c4 0d }

  condition:
    any of them
}