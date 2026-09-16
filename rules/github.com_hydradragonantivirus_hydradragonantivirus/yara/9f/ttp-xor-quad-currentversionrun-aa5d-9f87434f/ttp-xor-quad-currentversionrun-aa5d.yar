rule TTP_XOR_QUAD_CurrentVersionRun_aa5d {
  strings:
    $key_aa5d = { f9 32 [2] dd 3c [2] f6 10 [2] d8 32 [2] cc 29 [2] c3 33 [2] dd 2e [2] df 2f [2] c4 29 [2] d8 2e [2] c4 01 }

  condition:
    any of them
}