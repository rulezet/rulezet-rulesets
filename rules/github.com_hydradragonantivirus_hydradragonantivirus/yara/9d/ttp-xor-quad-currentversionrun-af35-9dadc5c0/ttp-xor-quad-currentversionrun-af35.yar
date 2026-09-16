rule TTP_XOR_QUAD_CurrentVersionRun_af35 {
  strings:
    $key_af35 = { fc 5a [2] d8 54 [2] f3 78 [2] dd 5a [2] c9 41 [2] c6 5b [2] d8 46 [2] da 47 [2] c1 41 [2] dd 46 [2] c1 69 }

  condition:
    any of them
}