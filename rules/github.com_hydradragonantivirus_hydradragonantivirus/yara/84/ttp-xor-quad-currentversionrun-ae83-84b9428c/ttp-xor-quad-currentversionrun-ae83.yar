rule TTP_XOR_QUAD_CurrentVersionRun_ae83 {
  strings:
    $key_ae83 = { fd ec [2] d9 e2 [2] f2 ce [2] dc ec [2] c8 f7 [2] c7 ed [2] d9 f0 [2] db f1 [2] c0 f7 [2] dc f0 [2] c0 df }

  condition:
    any of them
}