rule TTP_XOR_QUAD_CurrentVersionRun_2583 {
  strings:
    $key_2583 = { 76 ec [2] 52 e2 [2] 79 ce [2] 57 ec [2] 43 f7 [2] 4c ed [2] 52 f0 [2] 50 f1 [2] 4b f7 [2] 57 f0 [2] 4b df }

  condition:
    any of them
}