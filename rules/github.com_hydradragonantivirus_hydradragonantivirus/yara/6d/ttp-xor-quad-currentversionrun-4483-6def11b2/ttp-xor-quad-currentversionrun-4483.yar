rule TTP_XOR_QUAD_CurrentVersionRun_4483 {
  strings:
    $key_4483 = { 17 ec [2] 33 e2 [2] 18 ce [2] 36 ec [2] 22 f7 [2] 2d ed [2] 33 f0 [2] 31 f1 [2] 2a f7 [2] 36 f0 [2] 2a df }

  condition:
    any of them
}