rule TTP_XOR_QUAD_CurrentVersionRun_af7e {
  strings:
    $key_af7e = { fc 11 [2] d8 1f [2] f3 33 [2] dd 11 [2] c9 0a [2] c6 10 [2] d8 0d [2] da 0c [2] c1 0a [2] dd 0d [2] c1 22 }

  condition:
    any of them
}