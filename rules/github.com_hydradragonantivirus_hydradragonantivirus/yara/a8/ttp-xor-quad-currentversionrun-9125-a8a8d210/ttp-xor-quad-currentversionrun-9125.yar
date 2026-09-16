rule TTP_XOR_QUAD_CurrentVersionRun_9125 {
  strings:
    $key_9125 = { c2 4a [2] e6 44 [2] cd 68 [2] e3 4a [2] f7 51 [2] f8 4b [2] e6 56 [2] e4 57 [2] ff 51 [2] e3 56 [2] ff 79 }

  condition:
    any of them
}