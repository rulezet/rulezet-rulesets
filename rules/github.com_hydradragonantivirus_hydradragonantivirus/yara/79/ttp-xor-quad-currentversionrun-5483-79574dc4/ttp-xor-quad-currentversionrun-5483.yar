rule TTP_XOR_QUAD_CurrentVersionRun_5483 {
  strings:
    $key_5483 = { 07 ec [2] 23 e2 [2] 08 ce [2] 26 ec [2] 32 f7 [2] 3d ed [2] 23 f0 [2] 21 f1 [2] 3a f7 [2] 26 f0 [2] 3a df }

  condition:
    any of them
}