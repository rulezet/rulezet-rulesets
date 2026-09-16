rule TTP_XOR_QUAD_CurrentVersionRun_aa4d {
  strings:
    $key_aa4d = { f9 22 [2] dd 2c [2] f6 00 [2] d8 22 [2] cc 39 [2] c3 23 [2] dd 3e [2] df 3f [2] c4 39 [2] d8 3e [2] c4 11 }

  condition:
    any of them
}