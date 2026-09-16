rule TTP_XOR_QUAD_CurrentVersionRun_9126 {
  strings:
    $key_9126 = { c2 49 [2] e6 47 [2] cd 6b [2] e3 49 [2] f7 52 [2] f8 48 [2] e6 55 [2] e4 54 [2] ff 52 [2] e3 55 [2] ff 7a }

  condition:
    any of them
}