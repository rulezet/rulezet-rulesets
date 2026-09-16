rule TTP_XOR_QUAD_CurrentVersionRun_7983 {
  strings:
    $key_7983 = { 2a ec [2] 0e e2 [2] 25 ce [2] 0b ec [2] 1f f7 [2] 10 ed [2] 0e f0 [2] 0c f1 [2] 17 f7 [2] 0b f0 [2] 17 df }

  condition:
    any of them
}