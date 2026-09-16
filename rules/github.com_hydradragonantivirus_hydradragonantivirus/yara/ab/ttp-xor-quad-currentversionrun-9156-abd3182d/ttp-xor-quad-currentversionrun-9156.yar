rule TTP_XOR_QUAD_CurrentVersionRun_9156 {
  strings:
    $key_9156 = { c2 39 [2] e6 37 [2] cd 1b [2] e3 39 [2] f7 22 [2] f8 38 [2] e6 25 [2] e4 24 [2] ff 22 [2] e3 25 [2] ff 0a }

  condition:
    any of them
}