rule TTP_XOR_QUAD_CurrentVersionRun_9235 {
  strings:
    $key_9235 = { c1 5a [2] e5 54 [2] ce 78 [2] e0 5a [2] f4 41 [2] fb 5b [2] e5 46 [2] e7 47 [2] fc 41 [2] e0 46 [2] fc 69 }

  condition:
    any of them
}