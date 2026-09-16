rule TTP_XOR_QUAD_CurrentVersionRun_af4f {
  strings:
    $key_af4f = { fc 20 [2] d8 2e [2] f3 02 [2] dd 20 [2] c9 3b [2] c6 21 [2] d8 3c [2] da 3d [2] c1 3b [2] dd 3c [2] c1 13 }

  condition:
    any of them
}