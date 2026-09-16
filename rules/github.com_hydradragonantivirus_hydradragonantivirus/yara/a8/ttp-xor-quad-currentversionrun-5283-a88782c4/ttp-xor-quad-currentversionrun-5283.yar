rule TTP_XOR_QUAD_CurrentVersionRun_5283 {
  strings:
    $key_5283 = { 01 ec [2] 25 e2 [2] 0e ce [2] 20 ec [2] 34 f7 [2] 3b ed [2] 25 f0 [2] 27 f1 [2] 3c f7 [2] 20 f0 [2] 3c df }

  condition:
    any of them
}