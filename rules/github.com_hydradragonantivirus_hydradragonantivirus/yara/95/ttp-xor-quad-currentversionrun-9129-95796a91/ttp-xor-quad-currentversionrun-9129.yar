rule TTP_XOR_QUAD_CurrentVersionRun_9129 {
  strings:
    $key_9129 = { c2 46 [2] e6 48 [2] cd 64 [2] e3 46 [2] f7 5d [2] f8 47 [2] e6 5a [2] e4 5b [2] ff 5d [2] e3 5a [2] ff 75 }

  condition:
    any of them
}