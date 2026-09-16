rule TTP_XOR_QUAD_CurrentVersionRun_9119 {
  strings:
    $key_9119 = { c2 76 [2] e6 78 [2] cd 54 [2] e3 76 [2] f7 6d [2] f8 77 [2] e6 6a [2] e4 6b [2] ff 6d [2] e3 6a [2] ff 45 }

  condition:
    any of them
}