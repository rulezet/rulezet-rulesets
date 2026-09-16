rule TTP_XOR_QUAD_CurrentVersionRun_9210 {
  strings:
    $key_9210 = { c1 7f [2] e5 71 [2] ce 5d [2] e0 7f [2] f4 64 [2] fb 7e [2] e5 63 [2] e7 62 [2] fc 64 [2] e0 63 [2] fc 4c }

  condition:
    any of them
}