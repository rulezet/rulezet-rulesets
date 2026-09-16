rule TTP_XOR_QUAD_CurrentVersionRun_afe5 {
  strings:
    $key_afe5 = { fc 8a [2] d8 84 [2] f3 a8 [2] dd 8a [2] c9 91 [2] c6 8b [2] d8 96 [2] da 97 [2] c1 91 [2] dd 96 [2] c1 b9 }

  condition:
    any of them
}