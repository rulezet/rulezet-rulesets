rule TTP_XOR_QUAD_CurrentVersionRun_aa7f {
  strings:
    $key_aa7f = { f9 10 [2] dd 1e [2] f6 32 [2] d8 10 [2] cc 0b [2] c3 11 [2] dd 0c [2] df 0d [2] c4 0b [2] d8 0c [2] c4 23 }

  condition:
    any of them
}