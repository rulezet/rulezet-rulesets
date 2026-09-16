rule TTP_XOR_QUAD_CurrentVersionRun_956b {
  strings:
    $key_956b = { c6 04 [2] e2 0a [2] c9 26 [2] e7 04 [2] f3 1f [2] fc 05 [2] e2 18 [2] e0 19 [2] fb 1f [2] e7 18 [2] fb 37 }

  condition:
    any of them
}