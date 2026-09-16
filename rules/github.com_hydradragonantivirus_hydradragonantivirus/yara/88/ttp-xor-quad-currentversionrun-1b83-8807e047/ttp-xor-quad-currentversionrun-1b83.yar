rule TTP_XOR_QUAD_CurrentVersionRun_1b83 {
  strings:
    $key_1b83 = { 48 ec [2] 6c e2 [2] 47 ce [2] 69 ec [2] 7d f7 [2] 72 ed [2] 6c f0 [2] 6e f1 [2] 75 f7 [2] 69 f0 [2] 75 df }

  condition:
    any of them
}