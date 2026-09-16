rule TTP_XOR_QUAD_CurrentVersionRun_afeb {
  strings:
    $key_afeb = { fc 84 [2] d8 8a [2] f3 a6 [2] dd 84 [2] c9 9f [2] c6 85 [2] d8 98 [2] da 99 [2] c1 9f [2] dd 98 [2] c1 b7 }

  condition:
    any of them
}