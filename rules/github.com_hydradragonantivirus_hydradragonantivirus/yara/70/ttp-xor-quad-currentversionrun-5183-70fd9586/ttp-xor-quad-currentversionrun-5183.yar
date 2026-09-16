rule TTP_XOR_QUAD_CurrentVersionRun_5183 {
  strings:
    $key_5183 = { 02 ec [2] 26 e2 [2] 0d ce [2] 23 ec [2] 37 f7 [2] 38 ed [2] 26 f0 [2] 24 f1 [2] 3f f7 [2] 23 f0 [2] 3f df }

  condition:
    any of them
}