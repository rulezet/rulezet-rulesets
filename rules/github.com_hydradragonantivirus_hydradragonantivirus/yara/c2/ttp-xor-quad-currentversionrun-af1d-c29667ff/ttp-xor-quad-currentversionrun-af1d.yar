rule TTP_XOR_QUAD_CurrentVersionRun_af1d {
  strings:
    $key_af1d = { fc 72 [2] d8 7c [2] f3 50 [2] dd 72 [2] c9 69 [2] c6 73 [2] d8 6e [2] da 6f [2] c1 69 [2] dd 6e [2] c1 41 }

  condition:
    any of them
}