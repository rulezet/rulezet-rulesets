rule TTP_XOR_QUAD_CurrentVersionRun_1883 {
  strings:
    $key_1883 = { 4b ec [2] 6f e2 [2] 44 ce [2] 6a ec [2] 7e f7 [2] 71 ed [2] 6f f0 [2] 6d f1 [2] 76 f7 [2] 6a f0 [2] 76 df }

  condition:
    any of them
}