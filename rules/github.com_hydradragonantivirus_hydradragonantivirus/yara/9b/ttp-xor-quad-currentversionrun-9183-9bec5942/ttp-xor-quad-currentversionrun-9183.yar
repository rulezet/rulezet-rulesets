rule TTP_XOR_QUAD_CurrentVersionRun_9183 {
  strings:
    $key_9183 = { c2 ec [2] e6 e2 [2] cd ce [2] e3 ec [2] f7 f7 [2] f8 ed [2] e6 f0 [2] e4 f1 [2] ff f7 [2] e3 f0 [2] ff df }

  condition:
    any of them
}