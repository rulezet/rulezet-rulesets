rule TTP_XOR_QUAD_CurrentVersionRun_9155 {
  strings:
    $key_9155 = { c2 3a [2] e6 34 [2] cd 18 [2] e3 3a [2] f7 21 [2] f8 3b [2] e6 26 [2] e4 27 [2] ff 21 [2] e3 26 [2] ff 09 }

  condition:
    any of them
}