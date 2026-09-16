rule TTP_XOR_QUAD_CurrentVersionRun_aa61 {
  strings:
    $key_aa61 = { f9 0e [2] dd 00 [2] f6 2c [2] d8 0e [2] cc 15 [2] c3 0f [2] dd 12 [2] df 13 [2] c4 15 [2] d8 12 [2] c4 3d }

  condition:
    any of them
}