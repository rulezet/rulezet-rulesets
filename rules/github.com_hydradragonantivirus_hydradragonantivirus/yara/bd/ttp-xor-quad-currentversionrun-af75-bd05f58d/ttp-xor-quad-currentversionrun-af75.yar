rule TTP_XOR_QUAD_CurrentVersionRun_af75 {
  strings:
    $key_af75 = { fc 1a [2] d8 14 [2] f3 38 [2] dd 1a [2] c9 01 [2] c6 1b [2] d8 06 [2] da 07 [2] c1 01 [2] dd 06 [2] c1 29 }

  condition:
    any of them
}