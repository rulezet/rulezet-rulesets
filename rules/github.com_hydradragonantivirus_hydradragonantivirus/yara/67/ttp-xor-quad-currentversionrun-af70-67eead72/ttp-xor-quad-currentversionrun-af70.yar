rule TTP_XOR_QUAD_CurrentVersionRun_af70 {
  strings:
    $key_af70 = { fc 1f [2] d8 11 [2] f3 3d [2] dd 1f [2] c9 04 [2] c6 1e [2] d8 03 [2] da 02 [2] c1 04 [2] dd 03 [2] c1 2c }

  condition:
    any of them
}