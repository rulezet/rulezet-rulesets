rule TTP_XOR_QUAD_CurrentVersionRun_92e2 {
  strings:
    $key_92e2 = { c1 8d [2] e5 83 [2] ce af [2] e0 8d [2] f4 96 [2] fb 8c [2] e5 91 [2] e7 90 [2] fc 96 [2] e0 91 [2] fc be }

  condition:
    any of them
}