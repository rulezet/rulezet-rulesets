rule TTP_XOR_QUAD_CurrentVersionRun_aa7d {
  strings:
    $key_aa7d = { f9 12 [2] dd 1c [2] f6 30 [2] d8 12 [2] cc 09 [2] c3 13 [2] dd 0e [2] df 0f [2] c4 09 [2] d8 0e [2] c4 21 }

  condition:
    any of them
}