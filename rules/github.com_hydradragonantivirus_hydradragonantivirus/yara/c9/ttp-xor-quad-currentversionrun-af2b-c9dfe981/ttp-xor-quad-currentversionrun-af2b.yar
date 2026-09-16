rule TTP_XOR_QUAD_CurrentVersionRun_af2b {
  strings:
    $key_af2b = { fc 44 [2] d8 4a [2] f3 66 [2] dd 44 [2] c9 5f [2] c6 45 [2] d8 58 [2] da 59 [2] c1 5f [2] dd 58 [2] c1 77 }

  condition:
    any of them
}