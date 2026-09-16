rule TTP_XOR_QUAD_CurrentVersionRun_af7a {
  strings:
    $key_af7a = { fc 15 [2] d8 1b [2] f3 37 [2] dd 15 [2] c9 0e [2] c6 14 [2] d8 09 [2] da 08 [2] c1 0e [2] dd 09 [2] c1 26 }

  condition:
    any of them
}