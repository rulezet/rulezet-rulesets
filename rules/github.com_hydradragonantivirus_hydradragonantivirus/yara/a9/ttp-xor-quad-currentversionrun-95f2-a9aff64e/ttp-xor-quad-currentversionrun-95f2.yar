rule TTP_XOR_QUAD_CurrentVersionRun_95f2 {
  strings:
    $key_95f2 = { c6 9d [2] e2 93 [2] c9 bf [2] e7 9d [2] f3 86 [2] fc 9c [2] e2 81 [2] e0 80 [2] fb 86 [2] e7 81 [2] fb ae }

  condition:
    any of them
}