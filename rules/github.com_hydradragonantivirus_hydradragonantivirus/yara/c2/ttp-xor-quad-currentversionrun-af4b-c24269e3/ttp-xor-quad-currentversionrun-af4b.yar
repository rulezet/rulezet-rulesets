rule TTP_XOR_QUAD_CurrentVersionRun_af4b {
  strings:
    $key_af4b = { fc 24 [2] d8 2a [2] f3 06 [2] dd 24 [2] c9 3f [2] c6 25 [2] d8 38 [2] da 39 [2] c1 3f [2] dd 38 [2] c1 17 }

  condition:
    any of them
}