rule TTP_XOR_QUAD_CurrentVersionRun_925b {
  strings:
    $key_925b = { c1 34 [2] e5 3a [2] ce 16 [2] e0 34 [2] f4 2f [2] fb 35 [2] e5 28 [2] e7 29 [2] fc 2f [2] e0 28 [2] fc 07 }

  condition:
    any of them
}