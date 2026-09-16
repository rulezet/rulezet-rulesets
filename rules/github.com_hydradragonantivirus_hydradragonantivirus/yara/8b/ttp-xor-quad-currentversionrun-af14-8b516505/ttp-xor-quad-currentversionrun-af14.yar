rule TTP_XOR_QUAD_CurrentVersionRun_af14 {
  strings:
    $key_af14 = { fc 7b [2] d8 75 [2] f3 59 [2] dd 7b [2] c9 60 [2] c6 7a [2] d8 67 [2] da 66 [2] c1 60 [2] dd 67 [2] c1 48 }

  condition:
    any of them
}