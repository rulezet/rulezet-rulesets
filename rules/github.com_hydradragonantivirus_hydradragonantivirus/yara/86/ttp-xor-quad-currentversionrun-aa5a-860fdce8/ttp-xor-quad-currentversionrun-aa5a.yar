rule TTP_XOR_QUAD_CurrentVersionRun_aa5a {
  strings:
    $key_aa5a = { f9 35 [2] dd 3b [2] f6 17 [2] d8 35 [2] cc 2e [2] c3 34 [2] dd 29 [2] df 28 [2] c4 2e [2] d8 29 [2] c4 06 }

  condition:
    any of them
}