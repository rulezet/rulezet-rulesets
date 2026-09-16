rule TTP_XOR_QUAD_CurrentVersionRun_aa40 {
  strings:
    $key_aa40 = { f9 2f [2] dd 21 [2] f6 0d [2] d8 2f [2] cc 34 [2] c3 2e [2] dd 33 [2] df 32 [2] c4 34 [2] d8 33 [2] c4 1c }

  condition:
    any of them
}