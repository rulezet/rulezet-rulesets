rule TTP_XOR_QUAD_CurrentVersionRun_af26 {
  strings:
    $key_af26 = { fc 49 [2] d8 47 [2] f3 6b [2] dd 49 [2] c9 52 [2] c6 48 [2] d8 55 [2] da 54 [2] c1 52 [2] dd 55 [2] c1 7a }

  condition:
    any of them
}