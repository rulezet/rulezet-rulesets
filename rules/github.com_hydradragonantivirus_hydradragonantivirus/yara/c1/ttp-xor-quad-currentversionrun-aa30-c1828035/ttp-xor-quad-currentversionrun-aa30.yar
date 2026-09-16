rule TTP_XOR_QUAD_CurrentVersionRun_aa30 {
  strings:
    $key_aa30 = { f9 5f [2] dd 51 [2] f6 7d [2] d8 5f [2] cc 44 [2] c3 5e [2] dd 43 [2] df 42 [2] c4 44 [2] d8 43 [2] c4 6c }

  condition:
    any of them
}