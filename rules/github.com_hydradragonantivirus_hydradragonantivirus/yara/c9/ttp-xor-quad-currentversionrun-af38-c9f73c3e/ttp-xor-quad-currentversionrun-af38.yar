rule TTP_XOR_QUAD_CurrentVersionRun_af38 {
  strings:
    $key_af38 = { fc 57 [2] d8 59 [2] f3 75 [2] dd 57 [2] c9 4c [2] c6 56 [2] d8 4b [2] da 4a [2] c1 4c [2] dd 4b [2] c1 64 }

  condition:
    any of them
}