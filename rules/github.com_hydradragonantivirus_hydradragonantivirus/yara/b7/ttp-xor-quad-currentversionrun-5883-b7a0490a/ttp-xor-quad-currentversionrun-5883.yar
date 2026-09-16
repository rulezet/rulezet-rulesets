rule TTP_XOR_QUAD_CurrentVersionRun_5883 {
  strings:
    $key_5883 = { 0b ec [2] 2f e2 [2] 04 ce [2] 2a ec [2] 3e f7 [2] 31 ed [2] 2f f0 [2] 2d f1 [2] 36 f7 [2] 2a f0 [2] 36 df }

  condition:
    any of them
}