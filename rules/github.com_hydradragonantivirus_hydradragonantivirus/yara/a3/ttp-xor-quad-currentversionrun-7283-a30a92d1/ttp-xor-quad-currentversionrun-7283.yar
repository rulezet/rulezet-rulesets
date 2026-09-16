rule TTP_XOR_QUAD_CurrentVersionRun_7283 {
  strings:
    $key_7283 = { 21 ec [2] 05 e2 [2] 2e ce [2] 00 ec [2] 14 f7 [2] 1b ed [2] 05 f0 [2] 07 f1 [2] 1c f7 [2] 00 f0 [2] 1c df }

  condition:
    any of them
}