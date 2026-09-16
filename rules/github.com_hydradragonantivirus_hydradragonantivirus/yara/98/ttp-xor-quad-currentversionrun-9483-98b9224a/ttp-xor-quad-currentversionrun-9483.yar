rule TTP_XOR_QUAD_CurrentVersionRun_9483 {
  strings:
    $key_9483 = { c7 ec [2] e3 e2 [2] c8 ce [2] e6 ec [2] f2 f7 [2] fd ed [2] e3 f0 [2] e1 f1 [2] fa f7 [2] e6 f0 [2] fa df }

  condition:
    any of them
}