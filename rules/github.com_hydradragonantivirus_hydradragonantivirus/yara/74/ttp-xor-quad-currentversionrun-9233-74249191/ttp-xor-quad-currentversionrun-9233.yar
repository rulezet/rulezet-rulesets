rule TTP_XOR_QUAD_CurrentVersionRun_9233 {
  strings:
    $key_9233 = { c1 5c [2] e5 52 [2] ce 7e [2] e0 5c [2] f4 47 [2] fb 5d [2] e5 40 [2] e7 41 [2] fc 47 [2] e0 40 [2] fc 6f }

  condition:
    any of them
}