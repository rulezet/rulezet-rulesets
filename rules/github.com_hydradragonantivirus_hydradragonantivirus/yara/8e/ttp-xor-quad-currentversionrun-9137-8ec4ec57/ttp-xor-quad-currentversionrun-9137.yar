rule TTP_XOR_QUAD_CurrentVersionRun_9137 {
  strings:
    $key_9137 = { c2 58 [2] e6 56 [2] cd 7a [2] e3 58 [2] f7 43 [2] f8 59 [2] e6 44 [2] e4 45 [2] ff 43 [2] e3 44 [2] ff 6b }

  condition:
    any of them
}