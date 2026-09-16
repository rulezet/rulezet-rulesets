rule TTP_XOR_QUAD_CurrentVersionRun_af23 {
  strings:
    $key_af23 = { fc 4c [2] d8 42 [2] f3 6e [2] dd 4c [2] c9 57 [2] c6 4d [2] d8 50 [2] da 51 [2] c1 57 [2] dd 50 [2] c1 7f }

  condition:
    any of them
}