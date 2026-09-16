rule TTP_XOR_QUAD_CurrentVersionRun_afce {
  strings:
    $key_afce = { fc a1 [2] d8 af [2] f3 83 [2] dd a1 [2] c9 ba [2] c6 a0 [2] d8 bd [2] da bc [2] c1 ba [2] dd bd [2] c1 92 }

  condition:
    any of them
}