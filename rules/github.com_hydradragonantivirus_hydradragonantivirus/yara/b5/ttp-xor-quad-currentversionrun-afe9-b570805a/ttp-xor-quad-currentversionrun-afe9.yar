rule TTP_XOR_QUAD_CurrentVersionRun_afe9 {
  strings:
    $key_afe9 = { fc 86 [2] d8 88 [2] f3 a4 [2] dd 86 [2] c9 9d [2] c6 87 [2] d8 9a [2] da 9b [2] c1 9d [2] dd 9a [2] c1 b5 }

  condition:
    any of them
}