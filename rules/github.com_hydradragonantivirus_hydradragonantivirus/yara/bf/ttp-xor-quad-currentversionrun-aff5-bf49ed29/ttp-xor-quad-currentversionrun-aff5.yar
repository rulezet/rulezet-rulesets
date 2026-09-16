rule TTP_XOR_QUAD_CurrentVersionRun_aff5 {
  strings:
    $key_aff5 = { fc 9a [2] d8 94 [2] f3 b8 [2] dd 9a [2] c9 81 [2] c6 9b [2] d8 86 [2] da 87 [2] c1 81 [2] dd 86 [2] c1 a9 }

  condition:
    any of them
}