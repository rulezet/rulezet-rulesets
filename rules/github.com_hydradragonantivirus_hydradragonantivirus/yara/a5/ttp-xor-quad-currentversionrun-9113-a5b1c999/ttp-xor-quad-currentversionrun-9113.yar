rule TTP_XOR_QUAD_CurrentVersionRun_9113 {
  strings:
    $key_9113 = { c2 7c [2] e6 72 [2] cd 5e [2] e3 7c [2] f7 67 [2] f8 7d [2] e6 60 [2] e4 61 [2] ff 67 [2] e3 60 [2] ff 4f }

  condition:
    any of them
}