rule TTP_XOR_QUAD_CurrentVersionRun_925a {
  strings:
    $key_925a = { c1 35 [2] e5 3b [2] ce 17 [2] e0 35 [2] f4 2e [2] fb 34 [2] e5 29 [2] e7 28 [2] fc 2e [2] e0 29 [2] fc 06 }

  condition:
    any of them
}