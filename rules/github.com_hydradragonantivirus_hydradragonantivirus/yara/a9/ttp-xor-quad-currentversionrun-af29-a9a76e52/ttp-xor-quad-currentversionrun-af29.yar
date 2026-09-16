rule TTP_XOR_QUAD_CurrentVersionRun_af29 {
  strings:
    $key_af29 = { fc 46 [2] d8 48 [2] f3 64 [2] dd 46 [2] c9 5d [2] c6 47 [2] d8 5a [2] da 5b [2] c1 5d [2] dd 5a [2] c1 75 }

  condition:
    any of them
}