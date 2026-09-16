rule TTP_XOR_QUAD_CurrentVersionRun_af78 {
  strings:
    $key_af78 = { fc 17 [2] d8 19 [2] f3 35 [2] dd 17 [2] c9 0c [2] c6 16 [2] d8 0b [2] da 0a [2] c1 0c [2] dd 0b [2] c1 24 }

  condition:
    any of them
}