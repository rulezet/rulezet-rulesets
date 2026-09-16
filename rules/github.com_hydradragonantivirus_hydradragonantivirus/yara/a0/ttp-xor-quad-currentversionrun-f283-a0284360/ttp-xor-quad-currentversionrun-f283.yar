rule TTP_XOR_QUAD_CurrentVersionRun_f283 {
  strings:
    $key_f283 = { a1 ec [2] 85 e2 [2] ae ce [2] 80 ec [2] 94 f7 [2] 9b ed [2] 85 f0 [2] 87 f1 [2] 9c f7 [2] 80 f0 [2] 9c df }

  condition:
    any of them
}