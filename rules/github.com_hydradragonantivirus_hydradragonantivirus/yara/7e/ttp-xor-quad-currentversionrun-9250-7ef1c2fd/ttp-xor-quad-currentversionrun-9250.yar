rule TTP_XOR_QUAD_CurrentVersionRun_9250 {
  strings:
    $key_9250 = { c1 3f [2] e5 31 [2] ce 1d [2] e0 3f [2] f4 24 [2] fb 3e [2] e5 23 [2] e7 22 [2] fc 24 [2] e0 23 [2] fc 0c }

  condition:
    any of them
}