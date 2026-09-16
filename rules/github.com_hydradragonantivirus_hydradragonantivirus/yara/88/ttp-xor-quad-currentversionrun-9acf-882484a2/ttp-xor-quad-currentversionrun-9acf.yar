rule TTP_XOR_QUAD_CurrentVersionRun_9acf {
  strings:
    $key_9acf = { c9 a0 [2] ed ae [2] c6 82 [2] e8 a0 [2] fc bb [2] f3 a1 [2] ed bc [2] ef bd [2] f4 bb [2] e8 bc [2] f4 93 }

  condition:
    any of them
}