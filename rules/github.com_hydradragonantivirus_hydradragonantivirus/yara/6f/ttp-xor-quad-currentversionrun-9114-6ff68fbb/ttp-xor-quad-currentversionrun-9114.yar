rule TTP_XOR_QUAD_CurrentVersionRun_9114 {
  strings:
    $key_9114 = { c2 7b [2] e6 75 [2] cd 59 [2] e3 7b [2] f7 60 [2] f8 7a [2] e6 67 [2] e4 66 [2] ff 60 [2] e3 67 [2] ff 48 }

  condition:
    any of them
}