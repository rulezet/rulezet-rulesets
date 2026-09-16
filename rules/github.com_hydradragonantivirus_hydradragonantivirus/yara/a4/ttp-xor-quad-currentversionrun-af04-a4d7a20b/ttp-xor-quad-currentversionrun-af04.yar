rule TTP_XOR_QUAD_CurrentVersionRun_af04 {
  strings:
    $key_af04 = { fc 6b [2] d8 65 [2] f3 49 [2] dd 6b [2] c9 70 [2] c6 6a [2] d8 77 [2] da 76 [2] c1 70 [2] dd 77 [2] c1 58 }

  condition:
    any of them
}