rule TTP_XOR_QUAD_CurrentVersionRun_af79 {
  strings:
    $key_af79 = { fc 16 [2] d8 18 [2] f3 34 [2] dd 16 [2] c9 0d [2] c6 17 [2] d8 0a [2] da 0b [2] c1 0d [2] dd 0a [2] c1 25 }

  condition:
    any of them
}