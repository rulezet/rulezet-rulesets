rule TTP_XOR_QUAD_CurrentVersionRun_9179 {
  strings:
    $key_9179 = { c2 16 [2] e6 18 [2] cd 34 [2] e3 16 [2] f7 0d [2] f8 17 [2] e6 0a [2] e4 0b [2] ff 0d [2] e3 0a [2] ff 25 }

  condition:
    any of them
}