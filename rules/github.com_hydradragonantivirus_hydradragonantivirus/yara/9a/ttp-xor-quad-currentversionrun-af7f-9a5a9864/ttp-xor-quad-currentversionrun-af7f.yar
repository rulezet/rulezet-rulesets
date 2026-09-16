rule TTP_XOR_QUAD_CurrentVersionRun_af7f {
  strings:
    $key_af7f = { fc 10 [2] d8 1e [2] f3 32 [2] dd 10 [2] c9 0b [2] c6 11 [2] d8 0c [2] da 0d [2] c1 0b [2] dd 0c [2] c1 23 }

  condition:
    any of them
}