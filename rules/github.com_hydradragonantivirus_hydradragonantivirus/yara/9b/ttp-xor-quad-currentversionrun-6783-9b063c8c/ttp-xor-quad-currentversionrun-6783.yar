rule TTP_XOR_QUAD_CurrentVersionRun_6783 {
  strings:
    $key_6783 = { 34 ec [2] 10 e2 [2] 3b ce [2] 15 ec [2] 01 f7 [2] 0e ed [2] 10 f0 [2] 12 f1 [2] 09 f7 [2] 15 f0 [2] 09 df }

  condition:
    any of them
}