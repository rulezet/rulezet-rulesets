rule TTP_XOR_QUAD_CurrentVersionRun_af33 {
  strings:
    $key_af33 = { fc 5c [2] d8 52 [2] f3 7e [2] dd 5c [2] c9 47 [2] c6 5d [2] d8 40 [2] da 41 [2] c1 47 [2] dd 40 [2] c1 6f }

  condition:
    any of them
}