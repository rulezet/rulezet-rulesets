rule TTP_XOR_QUAD_CurrentVersionRun_af5a {
  strings:
    $key_af5a = { fc 35 [2] d8 3b [2] f3 17 [2] dd 35 [2] c9 2e [2] c6 34 [2] d8 29 [2] da 28 [2] c1 2e [2] dd 29 [2] c1 06 }

  condition:
    any of them
}