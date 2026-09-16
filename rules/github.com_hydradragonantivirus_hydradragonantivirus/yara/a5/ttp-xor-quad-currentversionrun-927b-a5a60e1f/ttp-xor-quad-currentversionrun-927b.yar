rule TTP_XOR_QUAD_CurrentVersionRun_927b {
  strings:
    $key_927b = { c1 14 [2] e5 1a [2] ce 36 [2] e0 14 [2] f4 0f [2] fb 15 [2] e5 08 [2] e7 09 [2] fc 0f [2] e0 08 [2] fc 27 }

  condition:
    any of them
}