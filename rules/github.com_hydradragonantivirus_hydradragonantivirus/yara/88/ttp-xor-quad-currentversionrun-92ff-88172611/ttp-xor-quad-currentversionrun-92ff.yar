rule TTP_XOR_QUAD_CurrentVersionRun_92ff {
  strings:
    $key_92ff = { c1 90 [2] e5 9e [2] ce b2 [2] e0 90 [2] f4 8b [2] fb 91 [2] e5 8c [2] e7 8d [2] fc 8b [2] e0 8c [2] fc a3 }

  condition:
    any of them
}