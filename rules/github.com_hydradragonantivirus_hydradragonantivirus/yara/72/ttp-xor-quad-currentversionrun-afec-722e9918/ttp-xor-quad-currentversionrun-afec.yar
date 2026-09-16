rule TTP_XOR_QUAD_CurrentVersionRun_afec {
  strings:
    $key_afec = { fc 83 [2] d8 8d [2] f3 a1 [2] dd 83 [2] c9 98 [2] c6 82 [2] d8 9f [2] da 9e [2] c1 98 [2] dd 9f [2] c1 b0 }

  condition:
    any of them
}