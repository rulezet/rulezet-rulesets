rule TTP_XOR_QUAD_CurrentVersionRun_8583 {
  strings:
    $key_8583 = { d6 ec [2] f2 e2 [2] d9 ce [2] f7 ec [2] e3 f7 [2] ec ed [2] f2 f0 [2] f0 f1 [2] eb f7 [2] f7 f0 [2] eb df }

  condition:
    any of them
}