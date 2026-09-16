rule TTP_XOR_QUAD_CurrentVersionRun_92f4 {
  strings:
    $key_92f4 = { c1 9b [2] e5 95 [2] ce b9 [2] e0 9b [2] f4 80 [2] fb 9a [2] e5 87 [2] e7 86 [2] fc 80 [2] e0 87 [2] fc a8 }

  condition:
    any of them
}