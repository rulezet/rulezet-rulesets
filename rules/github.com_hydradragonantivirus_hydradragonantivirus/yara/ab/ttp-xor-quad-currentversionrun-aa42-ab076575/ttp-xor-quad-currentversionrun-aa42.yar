rule TTP_XOR_QUAD_CurrentVersionRun_aa42 {
  strings:
    $key_aa42 = { f9 2d [2] dd 23 [2] f6 0f [2] d8 2d [2] cc 36 [2] c3 2c [2] dd 31 [2] df 30 [2] c4 36 [2] d8 31 [2] c4 1e }

  condition:
    any of them
}