rule TTP_XOR_QUAD_CurrentVersionRun_af53 {
  strings:
    $key_af53 = { fc 3c [2] d8 32 [2] f3 1e [2] dd 3c [2] c9 27 [2] c6 3d [2] d8 20 [2] da 21 [2] c1 27 [2] dd 20 [2] c1 0f }

  condition:
    any of them
}