rule TTP_XOR_QUAD_CurrentVersionRun_951a {
  strings:
    $key_951a = { c6 75 [2] e2 7b [2] c9 57 [2] e7 75 [2] f3 6e [2] fc 74 [2] e2 69 [2] e0 68 [2] fb 6e [2] e7 69 [2] fb 46 }

  condition:
    any of them
}