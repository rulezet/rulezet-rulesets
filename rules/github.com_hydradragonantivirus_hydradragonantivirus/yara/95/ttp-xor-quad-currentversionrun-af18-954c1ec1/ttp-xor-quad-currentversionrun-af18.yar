rule TTP_XOR_QUAD_CurrentVersionRun_af18 {
  strings:
    $key_af18 = { fc 77 [2] d8 79 [2] f3 55 [2] dd 77 [2] c9 6c [2] c6 76 [2] d8 6b [2] da 6a [2] c1 6c [2] dd 6b [2] c1 44 }

  condition:
    any of them
}