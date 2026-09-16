rule TTP_XOR_QUAD_CurrentVersionRun_af03 {
  strings:
    $key_af03 = { fc 6c [2] d8 62 [2] f3 4e [2] dd 6c [2] c9 77 [2] c6 6d [2] d8 70 [2] da 71 [2] c1 77 [2] dd 70 [2] c1 5f }

  condition:
    any of them
}