rule TTP_XOR_QUAD_CurrentVersionRun_9383 {
  strings:
    $key_9383 = { c0 ec [2] e4 e2 [2] cf ce [2] e1 ec [2] f5 f7 [2] fa ed [2] e4 f0 [2] e6 f1 [2] fd f7 [2] e1 f0 [2] fd df }

  condition:
    any of them
}