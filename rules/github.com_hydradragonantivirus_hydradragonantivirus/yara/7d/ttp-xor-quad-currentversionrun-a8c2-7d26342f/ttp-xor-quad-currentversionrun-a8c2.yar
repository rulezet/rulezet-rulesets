rule TTP_XOR_QUAD_CurrentVersionRun_a8c2 {
  strings:
    $key_a8c2 = { fb ad [2] df a3 [2] f4 8f [2] da ad [2] ce b6 [2] c1 ac [2] df b1 [2] dd b0 [2] c6 b6 [2] da b1 [2] c6 9e }

  condition:
    any of them
}