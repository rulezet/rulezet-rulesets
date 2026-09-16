rule TTP_XOR_QUAD_CurrentVersionRun_e783 {
  strings:
    $key_e783 = { b4 ec [2] 90 e2 [2] bb ce [2] 95 ec [2] 81 f7 [2] 8e ed [2] 90 f0 [2] 92 f1 [2] 89 f7 [2] 95 f0 [2] 89 df }

  condition:
    any of them
}