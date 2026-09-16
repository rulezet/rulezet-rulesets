rule TTP_XOR_QUAD_CurrentVersionRun_af0b {
  strings:
    $key_af0b = { fc 64 [2] d8 6a [2] f3 46 [2] dd 64 [2] c9 7f [2] c6 65 [2] d8 78 [2] da 79 [2] c1 7f [2] dd 78 [2] c1 57 }

  condition:
    any of them
}