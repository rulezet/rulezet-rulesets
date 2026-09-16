rule TTP_XOR_QUAD_CurrentVersionRun_9166 {
  strings:
    $key_9166 = { c2 09 [2] e6 07 [2] cd 2b [2] e3 09 [2] f7 12 [2] f8 08 [2] e6 15 [2] e4 14 [2] ff 12 [2] e3 15 [2] ff 3a }

  condition:
    any of them
}