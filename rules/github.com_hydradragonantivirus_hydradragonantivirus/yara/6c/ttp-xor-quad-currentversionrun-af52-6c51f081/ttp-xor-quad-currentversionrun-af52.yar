rule TTP_XOR_QUAD_CurrentVersionRun_af52 {
  strings:
    $key_af52 = { fc 3d [2] d8 33 [2] f3 1f [2] dd 3d [2] c9 26 [2] c6 3c [2] d8 21 [2] da 20 [2] c1 26 [2] dd 21 [2] c1 0e }

  condition:
    any of them
}