rule TTP_XOR_QUAD_CurrentVersionRun_927d {
  strings:
    $key_927d = { c1 12 [2] e5 1c [2] ce 30 [2] e0 12 [2] f4 09 [2] fb 13 [2] e5 0e [2] e7 0f [2] fc 09 [2] e0 0e [2] fc 21 }

  condition:
    any of them
}