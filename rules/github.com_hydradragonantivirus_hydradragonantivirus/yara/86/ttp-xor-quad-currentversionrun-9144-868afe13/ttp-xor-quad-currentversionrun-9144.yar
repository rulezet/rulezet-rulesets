rule TTP_XOR_QUAD_CurrentVersionRun_9144 {
  strings:
    $key_9144 = { c2 2b [2] e6 25 [2] cd 09 [2] e3 2b [2] f7 30 [2] f8 2a [2] e6 37 [2] e4 36 [2] ff 30 [2] e3 37 [2] ff 18 }

  condition:
    any of them
}