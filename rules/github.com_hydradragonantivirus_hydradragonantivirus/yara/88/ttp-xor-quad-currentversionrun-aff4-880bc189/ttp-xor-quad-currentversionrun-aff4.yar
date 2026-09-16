rule TTP_XOR_QUAD_CurrentVersionRun_aff4 {
  strings:
    $key_aff4 = { fc 9b [2] d8 95 [2] f3 b9 [2] dd 9b [2] c9 80 [2] c6 9a [2] d8 87 [2] da 86 [2] c1 80 [2] dd 87 [2] c1 a8 }

  condition:
    any of them
}