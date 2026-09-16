rule TTP_XOR_QUAD_CurrentVersionRun_aa70 {
  strings:
    $key_aa70 = { f9 1f [2] dd 11 [2] f6 3d [2] d8 1f [2] cc 04 [2] c3 1e [2] dd 03 [2] df 02 [2] c4 04 [2] d8 03 [2] c4 2c }

  condition:
    any of them
}