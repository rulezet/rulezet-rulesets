rule TTP_XOR_QUAD_CurrentVersionRun_920c {
  strings:
    $key_920c = { c1 63 [2] e5 6d [2] ce 41 [2] e0 63 [2] f4 78 [2] fb 62 [2] e5 7f [2] e7 7e [2] fc 78 [2] e0 7f [2] fc 50 }

  condition:
    any of them
}