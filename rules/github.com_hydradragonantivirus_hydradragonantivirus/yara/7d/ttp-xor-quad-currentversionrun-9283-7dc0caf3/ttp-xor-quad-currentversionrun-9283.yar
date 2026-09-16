rule TTP_XOR_QUAD_CurrentVersionRun_9283 {
  strings:
    $key_9283 = { c1 ec [2] e5 e2 [2] ce ce [2] e0 ec [2] f4 f7 [2] fb ed [2] e5 f0 [2] e7 f1 [2] fc f7 [2] e0 f0 [2] fc df }

  condition:
    any of them
}