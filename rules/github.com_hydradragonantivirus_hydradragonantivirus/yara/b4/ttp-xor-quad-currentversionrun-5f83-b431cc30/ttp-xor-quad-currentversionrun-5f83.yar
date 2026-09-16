rule TTP_XOR_QUAD_CurrentVersionRun_5f83 {
  strings:
    $key_5f83 = { 0c ec [2] 28 e2 [2] 03 ce [2] 2d ec [2] 39 f7 [2] 36 ed [2] 28 f0 [2] 2a f1 [2] 31 f7 [2] 2d f0 [2] 31 df }

  condition:
    any of them
}