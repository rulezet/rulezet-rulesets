rule TTP_XOR_QUAD_CurrentVersionRun_3983 {
  strings:
    $key_3983 = { 6a ec [2] 4e e2 [2] 65 ce [2] 4b ec [2] 5f f7 [2] 50 ed [2] 4e f0 [2] 4c f1 [2] 57 f7 [2] 4b f0 [2] 57 df }

  condition:
    any of them
}