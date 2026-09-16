rule TTP_XOR_QUAD_CurrentVersionRun_0383 {
  strings:
    $key_0383 = { 50 ec [2] 74 e2 [2] 5f ce [2] 71 ec [2] 65 f7 [2] 6a ed [2] 74 f0 [2] 76 f1 [2] 6d f7 [2] 71 f0 [2] 6d df }

  condition:
    any of them
}