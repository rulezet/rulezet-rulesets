rule TTP_XOR_QUAD_CurrentVersionRun_951b {
  strings:
    $key_951b = { c6 74 [2] e2 7a [2] c9 56 [2] e7 74 [2] f3 6f [2] fc 75 [2] e2 68 [2] e0 69 [2] fb 6f [2] e7 68 [2] fb 47 }

  condition:
    any of them
}