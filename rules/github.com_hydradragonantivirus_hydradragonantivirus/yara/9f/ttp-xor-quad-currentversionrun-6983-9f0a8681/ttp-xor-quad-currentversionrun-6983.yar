rule TTP_XOR_QUAD_CurrentVersionRun_6983 {
  strings:
    $key_6983 = { 3a ec [2] 1e e2 [2] 35 ce [2] 1b ec [2] 0f f7 [2] 00 ed [2] 1e f0 [2] 1c f1 [2] 07 f7 [2] 1b f0 [2] 07 df }

  condition:
    any of them
}