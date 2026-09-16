rule TTP_XOR_QUAD_CurrentVersionRun_aa33 {
  strings:
    $key_aa33 = { f9 5c [2] dd 52 [2] f6 7e [2] d8 5c [2] cc 47 [2] c3 5d [2] dd 40 [2] df 41 [2] c4 47 [2] d8 40 [2] c4 6f }

  condition:
    any of them
}