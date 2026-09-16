rule TTP_XOR_QUAD_CurrentVersionRun_7583 {
  strings:
    $key_7583 = { 26 ec [2] 02 e2 [2] 29 ce [2] 07 ec [2] 13 f7 [2] 1c ed [2] 02 f0 [2] 00 f1 [2] 1b f7 [2] 07 f0 [2] 1b df }

  condition:
    any of them
}