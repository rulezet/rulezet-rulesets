rule TTP_XOR_QUAD_CurrentVersionRun_6483 {
  strings:
    $key_6483 = { 37 ec [2] 13 e2 [2] 38 ce [2] 16 ec [2] 02 f7 [2] 0d ed [2] 13 f0 [2] 11 f1 [2] 0a f7 [2] 16 f0 [2] 0a df }

  condition:
    any of them
}