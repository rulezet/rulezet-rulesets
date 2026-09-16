rule TTP_XOR_QUAD_CurrentVersionRun_afb4 {
  strings:
    $key_afb4 = { fc db [2] d8 d5 [2] f3 f9 [2] dd db [2] c9 c0 [2] c6 da [2] d8 c7 [2] da c6 [2] c1 c0 [2] dd c7 [2] c1 e8 }

  condition:
    any of them
}