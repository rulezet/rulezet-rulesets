rule TTP_XOR_QUAD_CurrentVersionRun_aa71 {
  strings:
    $key_aa71 = { f9 1e [2] dd 10 [2] f6 3c [2] d8 1e [2] cc 05 [2] c3 1f [2] dd 02 [2] df 03 [2] c4 05 [2] d8 02 [2] c4 2d }

  condition:
    any of them
}