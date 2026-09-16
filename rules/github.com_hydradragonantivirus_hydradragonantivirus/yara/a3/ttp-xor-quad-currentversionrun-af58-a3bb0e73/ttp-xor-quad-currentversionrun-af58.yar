rule TTP_XOR_QUAD_CurrentVersionRun_af58 {
  strings:
    $key_af58 = { fc 37 [2] d8 39 [2] f3 15 [2] dd 37 [2] c9 2c [2] c6 36 [2] d8 2b [2] da 2a [2] c1 2c [2] dd 2b [2] c1 04 }

  condition:
    any of them
}