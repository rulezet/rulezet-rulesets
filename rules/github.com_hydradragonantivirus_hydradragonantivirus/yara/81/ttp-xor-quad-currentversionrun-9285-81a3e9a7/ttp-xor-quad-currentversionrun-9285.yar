rule TTP_XOR_QUAD_CurrentVersionRun_9285 {
  strings:
    $key_9285 = { c1 ea [2] e5 e4 [2] ce c8 [2] e0 ea [2] f4 f1 [2] fb eb [2] e5 f6 [2] e7 f7 [2] fc f1 [2] e0 f6 [2] fc d9 }

  condition:
    any of them
}