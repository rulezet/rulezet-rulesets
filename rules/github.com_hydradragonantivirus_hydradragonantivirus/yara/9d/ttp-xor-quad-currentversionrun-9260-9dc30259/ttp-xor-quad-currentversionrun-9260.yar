rule TTP_XOR_QUAD_CurrentVersionRun_9260 {
  strings:
    $key_9260 = { c1 0f [2] e5 01 [2] ce 2d [2] e0 0f [2] f4 14 [2] fb 0e [2] e5 13 [2] e7 12 [2] fc 14 [2] e0 13 [2] fc 3c }

  condition:
    any of them
}