rule TTP_XOR_QUAD_CurrentVersionRun_3283 {
  strings:
    $key_3283 = { 61 ec [2] 45 e2 [2] 6e ce [2] 40 ec [2] 54 f7 [2] 5b ed [2] 45 f0 [2] 47 f1 [2] 5c f7 [2] 40 f0 [2] 5c df }

  condition:
    any of them
}