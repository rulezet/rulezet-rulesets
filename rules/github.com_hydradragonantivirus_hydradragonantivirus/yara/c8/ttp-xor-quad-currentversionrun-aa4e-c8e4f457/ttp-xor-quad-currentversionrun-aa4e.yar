rule TTP_XOR_QUAD_CurrentVersionRun_aa4e {
  strings:
    $key_aa4e = { f9 21 [2] dd 2f [2] f6 03 [2] d8 21 [2] cc 3a [2] c3 20 [2] dd 3d [2] df 3c [2] c4 3a [2] d8 3d [2] c4 12 }

  condition:
    any of them
}