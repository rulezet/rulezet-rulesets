rule TTP_XOR_QUAD_CurrentVersionRun_af5e {
  strings:
    $key_af5e = { fc 31 [2] d8 3f [2] f3 13 [2] dd 31 [2] c9 2a [2] c6 30 [2] d8 2d [2] da 2c [2] c1 2a [2] dd 2d [2] c1 02 }

  condition:
    any of them
}