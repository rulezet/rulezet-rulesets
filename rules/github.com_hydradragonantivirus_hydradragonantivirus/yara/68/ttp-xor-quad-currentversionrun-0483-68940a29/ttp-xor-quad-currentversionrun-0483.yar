rule TTP_XOR_QUAD_CurrentVersionRun_0483 {
  strings:
    $key_0483 = { 57 ec [2] 73 e2 [2] 58 ce [2] 76 ec [2] 62 f7 [2] 6d ed [2] 73 f0 [2] 71 f1 [2] 6a f7 [2] 76 f0 [2] 6a df }

  condition:
    any of them
}