rule TTP_XOR_QUAD_CurrentVersionRun_af76 {
  strings:
    $key_af76 = { fc 19 [2] d8 17 [2] f3 3b [2] dd 19 [2] c9 02 [2] c6 18 [2] d8 05 [2] da 04 [2] c1 02 [2] dd 05 [2] c1 2a }

  condition:
    any of them
}