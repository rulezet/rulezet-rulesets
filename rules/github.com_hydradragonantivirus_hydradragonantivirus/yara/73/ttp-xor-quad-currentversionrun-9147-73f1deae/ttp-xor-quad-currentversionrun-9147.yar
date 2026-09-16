rule TTP_XOR_QUAD_CurrentVersionRun_9147 {
  strings:
    $key_9147 = { c2 28 [2] e6 26 [2] cd 0a [2] e3 28 [2] f7 33 [2] f8 29 [2] e6 34 [2] e4 35 [2] ff 33 [2] e3 34 [2] ff 1b }

  condition:
    any of them
}