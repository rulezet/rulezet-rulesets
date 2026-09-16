rule TTP_XOR_QUAD_CurrentVersionRun_92fb {
  strings:
    $key_92fb = { c1 94 [2] e5 9a [2] ce b6 [2] e0 94 [2] f4 8f [2] fb 95 [2] e5 88 [2] e7 89 [2] fc 8f [2] e0 88 [2] fc a7 }

  condition:
    any of them
}