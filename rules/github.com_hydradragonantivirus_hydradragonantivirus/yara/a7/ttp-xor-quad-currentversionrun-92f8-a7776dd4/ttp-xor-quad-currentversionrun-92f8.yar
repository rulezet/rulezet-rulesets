rule TTP_XOR_QUAD_CurrentVersionRun_92f8 {
  strings:
    $key_92f8 = { c1 97 [2] e5 99 [2] ce b5 [2] e0 97 [2] f4 8c [2] fb 96 [2] e5 8b [2] e7 8a [2] fc 8c [2] e0 8b [2] fc a4 }

  condition:
    any of them
}