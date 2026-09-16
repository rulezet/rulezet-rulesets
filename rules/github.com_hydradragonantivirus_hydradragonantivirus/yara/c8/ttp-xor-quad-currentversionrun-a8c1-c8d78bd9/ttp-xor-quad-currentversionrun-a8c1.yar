rule TTP_XOR_QUAD_CurrentVersionRun_a8c1 {
  strings:
    $key_a8c1 = { fb ae [2] df a0 [2] f4 8c [2] da ae [2] ce b5 [2] c1 af [2] df b2 [2] dd b3 [2] c6 b5 [2] da b2 [2] c6 9d }

  condition:
    any of them
}