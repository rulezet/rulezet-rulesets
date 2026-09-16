rule TTP_XOR_QUAD_CurrentVersionRun_9154 {
  strings:
    $key_9154 = { c2 3b [2] e6 35 [2] cd 19 [2] e3 3b [2] f7 20 [2] f8 3a [2] e6 27 [2] e4 26 [2] ff 20 [2] e3 27 [2] ff 08 }

  condition:
    any of them
}