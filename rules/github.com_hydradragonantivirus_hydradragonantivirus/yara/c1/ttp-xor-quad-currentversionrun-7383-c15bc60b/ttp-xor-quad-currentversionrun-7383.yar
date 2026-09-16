rule TTP_XOR_QUAD_CurrentVersionRun_7383 {
  strings:
    $key_7383 = { 20 ec [2] 04 e2 [2] 2f ce [2] 01 ec [2] 15 f7 [2] 1a ed [2] 04 f0 [2] 06 f1 [2] 1d f7 [2] 01 f0 [2] 1d df }

  condition:
    any of them
}