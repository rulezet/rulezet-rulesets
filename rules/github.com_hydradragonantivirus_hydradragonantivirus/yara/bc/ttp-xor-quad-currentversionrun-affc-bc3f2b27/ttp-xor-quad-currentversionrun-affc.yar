rule TTP_XOR_QUAD_CurrentVersionRun_affc {
  strings:
    $key_affc = { fc 93 [2] d8 9d [2] f3 b1 [2] dd 93 [2] c9 88 [2] c6 92 [2] d8 8f [2] da 8e [2] c1 88 [2] dd 8f [2] c1 a0 }

  condition:
    any of them
}