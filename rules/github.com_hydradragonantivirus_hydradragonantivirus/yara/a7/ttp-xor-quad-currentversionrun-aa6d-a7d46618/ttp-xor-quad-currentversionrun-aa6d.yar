rule TTP_XOR_QUAD_CurrentVersionRun_aa6d {
  strings:
    $key_aa6d = { f9 02 [2] dd 0c [2] f6 20 [2] d8 02 [2] cc 19 [2] c3 03 [2] dd 1e [2] df 1f [2] c4 19 [2] d8 1e [2] c4 31 }

  condition:
    any of them
}