rule TTP_XOR_QUAD_CurrentVersionRun_af27 {
  strings:
    $key_af27 = { fc 48 [2] d8 46 [2] f3 6a [2] dd 48 [2] c9 53 [2] c6 49 [2] d8 54 [2] da 55 [2] c1 53 [2] dd 54 [2] c1 7b }

  condition:
    any of them
}