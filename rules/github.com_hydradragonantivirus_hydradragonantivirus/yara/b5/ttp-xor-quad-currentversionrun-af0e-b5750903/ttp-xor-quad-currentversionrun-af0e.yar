rule TTP_XOR_QUAD_CurrentVersionRun_af0e {
  strings:
    $key_af0e = { fc 61 [2] d8 6f [2] f3 43 [2] dd 61 [2] c9 7a [2] c6 60 [2] d8 7d [2] da 7c [2] c1 7a [2] dd 7d [2] c1 52 }

  condition:
    any of them
}