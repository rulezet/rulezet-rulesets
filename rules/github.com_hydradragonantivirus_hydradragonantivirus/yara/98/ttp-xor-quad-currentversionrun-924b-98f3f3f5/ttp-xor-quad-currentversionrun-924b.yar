rule TTP_XOR_QUAD_CurrentVersionRun_924b {
  strings:
    $key_924b = { c1 24 [2] e5 2a [2] ce 06 [2] e0 24 [2] f4 3f [2] fb 25 [2] e5 38 [2] e7 39 [2] fc 3f [2] e0 38 [2] fc 17 }

  condition:
    any of them
}