rule TTP_XOR_QUAD_CurrentVersionRun_9fcf {
  strings:
    $key_9fcf = { cc a0 [2] e8 ae [2] c3 82 [2] ed a0 [2] f9 bb [2] f6 a1 [2] e8 bc [2] ea bd [2] f1 bb [2] ed bc [2] f1 93 }

  condition:
    any of them
}