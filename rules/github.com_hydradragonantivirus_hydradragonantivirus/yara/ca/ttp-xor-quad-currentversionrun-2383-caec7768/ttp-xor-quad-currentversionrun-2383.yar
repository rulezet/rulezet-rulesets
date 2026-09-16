rule TTP_XOR_QUAD_CurrentVersionRun_2383 {
  strings:
    $key_2383 = { 70 ec [2] 54 e2 [2] 7f ce [2] 51 ec [2] 45 f7 [2] 4a ed [2] 54 f0 [2] 56 f1 [2] 4d f7 [2] 51 f0 [2] 4d df }

  condition:
    any of them
}