rule TTP_XOR_QUAD_CurrentVersionRun_af6c {
  strings:
    $key_af6c = { fc 03 [2] d8 0d [2] f3 21 [2] dd 03 [2] c9 18 [2] c6 02 [2] d8 1f [2] da 1e [2] c1 18 [2] dd 1f [2] c1 30 }

  condition:
    any of them
}