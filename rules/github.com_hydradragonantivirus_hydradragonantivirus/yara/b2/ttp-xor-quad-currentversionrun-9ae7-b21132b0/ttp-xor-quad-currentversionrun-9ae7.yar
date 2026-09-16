rule TTP_XOR_QUAD_CurrentVersionRun_9ae7 {
  strings:
    $key_9ae7 = { c9 88 [2] ed 86 [2] c6 aa [2] e8 88 [2] fc 93 [2] f3 89 [2] ed 94 [2] ef 95 [2] f4 93 [2] e8 94 [2] f4 bb }

  condition:
    any of them
}