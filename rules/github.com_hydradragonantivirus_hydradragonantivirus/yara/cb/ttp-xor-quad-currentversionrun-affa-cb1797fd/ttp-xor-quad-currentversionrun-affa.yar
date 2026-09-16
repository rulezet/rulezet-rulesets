rule TTP_XOR_QUAD_CurrentVersionRun_affa {
  strings:
    $key_affa = { fc 95 [2] d8 9b [2] f3 b7 [2] dd 95 [2] c9 8e [2] c6 94 [2] d8 89 [2] da 88 [2] c1 8e [2] dd 89 [2] c1 a6 }

  condition:
    any of them
}