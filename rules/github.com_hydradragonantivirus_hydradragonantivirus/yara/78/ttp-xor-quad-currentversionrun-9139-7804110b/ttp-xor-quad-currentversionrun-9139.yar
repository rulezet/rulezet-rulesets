rule TTP_XOR_QUAD_CurrentVersionRun_9139 {
  strings:
    $key_9139 = { c2 56 [2] e6 58 [2] cd 74 [2] e3 56 [2] f7 4d [2] f8 57 [2] e6 4a [2] e4 4b [2] ff 4d [2] e3 4a [2] ff 65 }

  condition:
    any of them
}