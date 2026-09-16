rule TTP_XOR_QUAD_CurrentVersionRun_aa7a {
  strings:
    $key_aa7a = { f9 15 [2] dd 1b [2] f6 37 [2] d8 15 [2] cc 0e [2] c3 14 [2] dd 09 [2] df 08 [2] c4 0e [2] d8 09 [2] c4 26 }

  condition:
    any of them
}