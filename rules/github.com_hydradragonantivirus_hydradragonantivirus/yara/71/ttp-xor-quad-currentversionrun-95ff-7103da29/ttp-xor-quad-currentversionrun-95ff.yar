rule TTP_XOR_QUAD_CurrentVersionRun_95ff {
  strings:
    $key_95ff = { c6 90 [2] e2 9e [2] c9 b2 [2] e7 90 [2] f3 8b [2] fc 91 [2] e2 8c [2] e0 8d [2] fb 8b [2] e7 8c [2] fb a3 }

  condition:
    any of them
}