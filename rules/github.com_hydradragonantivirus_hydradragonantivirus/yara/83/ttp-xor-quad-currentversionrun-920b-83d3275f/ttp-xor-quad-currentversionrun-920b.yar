rule TTP_XOR_QUAD_CurrentVersionRun_920b {
  strings:
    $key_920b = { c1 64 [2] e5 6a [2] ce 46 [2] e0 64 [2] f4 7f [2] fb 65 [2] e5 78 [2] e7 79 [2] fc 7f [2] e0 78 [2] fc 57 }

  condition:
    any of them
}