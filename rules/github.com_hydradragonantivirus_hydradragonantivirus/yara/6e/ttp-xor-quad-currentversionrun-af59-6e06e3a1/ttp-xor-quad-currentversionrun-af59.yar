rule TTP_XOR_QUAD_CurrentVersionRun_af59 {
  strings:
    $key_af59 = { fc 36 [2] d8 38 [2] f3 14 [2] dd 36 [2] c9 2d [2] c6 37 [2] d8 2a [2] da 2b [2] c1 2d [2] dd 2a [2] c1 05 }

  condition:
    any of them
}