rule TTP_XOR_QUAD_CurrentVersionRun_afe4 {
  strings:
    $key_afe4 = { fc 8b [2] d8 85 [2] f3 a9 [2] dd 8b [2] c9 90 [2] c6 8a [2] d8 97 [2] da 96 [2] c1 90 [2] dd 97 [2] c1 b8 }

  condition:
    any of them
}