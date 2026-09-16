rule TTP_XOR_QUAD_CurrentVersionRun_af01 {
  strings:
    $key_af01 = { fc 6e [2] d8 60 [2] f3 4c [2] dd 6e [2] c9 75 [2] c6 6f [2] d8 72 [2] da 73 [2] c1 75 [2] dd 72 [2] c1 5d }

  condition:
    any of them
}