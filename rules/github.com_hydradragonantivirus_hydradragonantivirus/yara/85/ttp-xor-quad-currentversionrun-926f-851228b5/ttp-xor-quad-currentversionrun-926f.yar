rule TTP_XOR_QUAD_CurrentVersionRun_926f {
  strings:
    $key_926f = { c1 00 [2] e5 0e [2] ce 22 [2] e0 00 [2] f4 1b [2] fb 01 [2] e5 1c [2] e7 1d [2] fc 1b [2] e0 1c [2] fc 33 }

  condition:
    any of them
}