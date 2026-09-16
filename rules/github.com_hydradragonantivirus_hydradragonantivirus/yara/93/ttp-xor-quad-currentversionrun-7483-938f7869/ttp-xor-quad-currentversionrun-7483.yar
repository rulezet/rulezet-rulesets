rule TTP_XOR_QUAD_CurrentVersionRun_7483 {
  strings:
    $key_7483 = { 27 ec [2] 03 e2 [2] 28 ce [2] 06 ec [2] 12 f7 [2] 1d ed [2] 03 f0 [2] 01 f1 [2] 1a f7 [2] 06 f0 [2] 1a df }

  condition:
    any of them
}