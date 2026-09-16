rule TTP_XOR_QUAD_CurrentVersionRun_92e7 {
  strings:
    $key_92e7 = { c1 88 [2] e5 86 [2] ce aa [2] e0 88 [2] f4 93 [2] fb 89 [2] e5 94 [2] e7 95 [2] fc 93 [2] e0 94 [2] fc bb }

  condition:
    any of them
}