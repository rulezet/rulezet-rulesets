rule TTP_XOR_QUAD_CurrentVersionRun_af7b {
  strings:
    $key_af7b = { fc 14 [2] d8 1a [2] f3 36 [2] dd 14 [2] c9 0f [2] c6 15 [2] d8 08 [2] da 09 [2] c1 0f [2] dd 08 [2] c1 27 }

  condition:
    any of them
}