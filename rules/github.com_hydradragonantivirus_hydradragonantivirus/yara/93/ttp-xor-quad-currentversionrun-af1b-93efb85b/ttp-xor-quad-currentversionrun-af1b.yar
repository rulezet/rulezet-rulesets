rule TTP_XOR_QUAD_CurrentVersionRun_af1b {
  strings:
    $key_af1b = { fc 74 [2] d8 7a [2] f3 56 [2] dd 74 [2] c9 6f [2] c6 75 [2] d8 68 [2] da 69 [2] c1 6f [2] dd 68 [2] c1 47 }

  condition:
    any of them
}