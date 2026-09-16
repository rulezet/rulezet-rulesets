rule TTP_XOR_QUAD_CurrentVersionRun_af56 {
  strings:
    $key_af56 = { fc 39 [2] d8 37 [2] f3 1b [2] dd 39 [2] c9 22 [2] c6 38 [2] d8 25 [2] da 24 [2] c1 22 [2] dd 25 [2] c1 0a }

  condition:
    any of them
}