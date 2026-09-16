rule TTP_XOR_QUAD_CurrentVersionRun_956d {
  strings:
    $key_956d = { c6 02 [2] e2 0c [2] c9 20 [2] e7 02 [2] f3 19 [2] fc 03 [2] e2 1e [2] e0 1f [2] fb 19 [2] e7 1e [2] fb 31 }

  condition:
    any of them
}