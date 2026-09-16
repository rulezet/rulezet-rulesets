rule TTP_XOR_QUAD_CurrentVersionRun_9184 {
  strings:
    $key_9184 = { c2 eb [2] e6 e5 [2] cd c9 [2] e3 eb [2] f7 f0 [2] f8 ea [2] e6 f7 [2] e4 f6 [2] ff f0 [2] e3 f7 [2] ff d8 }

  condition:
    any of them
}