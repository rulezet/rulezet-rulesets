rule TTP_XOR_QUAD_CurrentVersionRun_af07 {
  strings:
    $key_af07 = { fc 68 [2] d8 66 [2] f3 4a [2] dd 68 [2] c9 73 [2] c6 69 [2] d8 74 [2] da 75 [2] c1 73 [2] dd 74 [2] c1 5b }

  condition:
    any of them
}