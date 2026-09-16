rule TTP_XOR_QUAD_CurrentVersionRun_aa60 {
  strings:
    $key_aa60 = { f9 0f [2] dd 01 [2] f6 2d [2] d8 0f [2] cc 14 [2] c3 0e [2] dd 13 [2] df 12 [2] c4 14 [2] d8 13 [2] c4 3c }

  condition:
    any of them
}