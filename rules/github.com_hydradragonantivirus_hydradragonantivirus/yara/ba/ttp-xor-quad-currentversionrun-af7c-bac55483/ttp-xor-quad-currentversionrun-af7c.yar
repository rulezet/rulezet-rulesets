rule TTP_XOR_QUAD_CurrentVersionRun_af7c {
  strings:
    $key_af7c = { fc 13 [2] d8 1d [2] f3 31 [2] dd 13 [2] c9 08 [2] c6 12 [2] d8 0f [2] da 0e [2] c1 08 [2] dd 0f [2] c1 20 }

  condition:
    any of them
}