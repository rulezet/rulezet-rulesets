rule TTP_XOR_QUAD_CurrentVersionRun_86e7 {
  strings:
    $key_86e7 = { d5 88 [2] f1 86 [2] da aa [2] f4 88 [2] e0 93 [2] ef 89 [2] f1 94 [2] f3 95 [2] e8 93 [2] f4 94 [2] e8 bb }

  condition:
    any of them
}