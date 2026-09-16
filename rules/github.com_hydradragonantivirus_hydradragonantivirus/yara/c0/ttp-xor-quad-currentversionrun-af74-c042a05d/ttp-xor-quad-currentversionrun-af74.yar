rule TTP_XOR_QUAD_CurrentVersionRun_af74 {
  strings:
    $key_af74 = { fc 1b [2] d8 15 [2] f3 39 [2] dd 1b [2] c9 00 [2] c6 1a [2] d8 07 [2] da 06 [2] c1 00 [2] dd 07 [2] c1 28 }

  condition:
    any of them
}