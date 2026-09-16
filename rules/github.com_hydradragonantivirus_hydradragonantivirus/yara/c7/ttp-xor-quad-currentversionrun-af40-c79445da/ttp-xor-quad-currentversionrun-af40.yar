rule TTP_XOR_QUAD_CurrentVersionRun_af40 {
  strings:
    $key_af40 = { fc 2f [2] d8 21 [2] f3 0d [2] dd 2f [2] c9 34 [2] c6 2e [2] d8 33 [2] da 32 [2] c1 34 [2] dd 33 [2] c1 1c }

  condition:
    any of them
}