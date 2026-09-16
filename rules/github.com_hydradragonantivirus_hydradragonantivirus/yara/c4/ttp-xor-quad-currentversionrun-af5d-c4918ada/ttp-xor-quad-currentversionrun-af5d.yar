rule TTP_XOR_QUAD_CurrentVersionRun_af5d {
  strings:
    $key_af5d = { fc 32 [2] d8 3c [2] f3 10 [2] dd 32 [2] c9 29 [2] c6 33 [2] d8 2e [2] da 2f [2] c1 29 [2] dd 2e [2] c1 01 }

  condition:
    any of them
}