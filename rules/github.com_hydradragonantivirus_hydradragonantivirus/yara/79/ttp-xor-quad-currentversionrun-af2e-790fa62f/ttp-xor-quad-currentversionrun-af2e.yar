rule TTP_XOR_QUAD_CurrentVersionRun_af2e {
  strings:
    $key_af2e = { fc 41 [2] d8 4f [2] f3 63 [2] dd 41 [2] c9 5a [2] c6 40 [2] d8 5d [2] da 5c [2] c1 5a [2] dd 5d [2] c1 72 }

  condition:
    any of them
}