rule TTP_XOR_QUAD_CurrentVersionRun_9c83 {
  strings:
    $key_9c83 = { cf ec [2] eb e2 [2] c0 ce [2] ee ec [2] fa f7 [2] f5 ed [2] eb f0 [2] e9 f1 [2] f2 f7 [2] ee f0 [2] f2 df }

  condition:
    any of them
}