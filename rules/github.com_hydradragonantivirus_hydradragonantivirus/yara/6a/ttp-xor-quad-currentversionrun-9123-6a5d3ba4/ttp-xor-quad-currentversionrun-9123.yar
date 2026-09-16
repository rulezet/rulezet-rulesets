rule TTP_XOR_QUAD_CurrentVersionRun_9123 {
  strings:
    $key_9123 = { c2 4c [2] e6 42 [2] cd 6e [2] e3 4c [2] f7 57 [2] f8 4d [2] e6 50 [2] e4 51 [2] ff 57 [2] e3 50 [2] ff 7f }

  condition:
    any of them
}