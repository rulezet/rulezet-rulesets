rule TTP_XOR_QUAD_CurrentVersionRun_afc2 {
  strings:
    $key_afc2 = { fc ad [2] d8 a3 [2] f3 8f [2] dd ad [2] c9 b6 [2] c6 ac [2] d8 b1 [2] da b0 [2] c1 b6 [2] dd b1 [2] c1 9e }

  condition:
    any of them
}