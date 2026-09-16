rule TTP_XOR_QUAD_CurrentVersionRun_91e7 {
  strings:
    $key_91e7 = { c2 88 [2] e6 86 [2] cd aa [2] e3 88 [2] f7 93 [2] f8 89 [2] e6 94 [2] e4 95 [2] ff 93 [2] e3 94 [2] ff bb }

  condition:
    any of them
}