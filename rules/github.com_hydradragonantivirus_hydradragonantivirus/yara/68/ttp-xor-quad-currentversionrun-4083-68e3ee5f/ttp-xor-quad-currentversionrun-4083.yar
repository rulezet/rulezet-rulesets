rule TTP_XOR_QUAD_CurrentVersionRun_4083 {
  strings:
    $key_4083 = { 13 ec [2] 37 e2 [2] 1c ce [2] 32 ec [2] 26 f7 [2] 29 ed [2] 37 f0 [2] 35 f1 [2] 2e f7 [2] 32 f0 [2] 2e df }

  condition:
    any of them
}