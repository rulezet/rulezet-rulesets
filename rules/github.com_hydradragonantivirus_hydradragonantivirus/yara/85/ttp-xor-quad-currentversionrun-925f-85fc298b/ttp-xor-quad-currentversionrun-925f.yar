rule TTP_XOR_QUAD_CurrentVersionRun_925f {
  strings:
    $key_925f = { c1 30 [2] e5 3e [2] ce 12 [2] e0 30 [2] f4 2b [2] fb 31 [2] e5 2c [2] e7 2d [2] fc 2b [2] e0 2c [2] fc 03 }

  condition:
    any of them
}