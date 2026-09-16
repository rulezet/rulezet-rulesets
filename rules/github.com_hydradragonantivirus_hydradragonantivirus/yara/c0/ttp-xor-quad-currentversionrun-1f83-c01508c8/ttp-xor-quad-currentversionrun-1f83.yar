rule TTP_XOR_QUAD_CurrentVersionRun_1f83 {
  strings:
    $key_1f83 = { 4c ec [2] 68 e2 [2] 43 ce [2] 6d ec [2] 79 f7 [2] 76 ed [2] 68 f0 [2] 6a f1 [2] 71 f7 [2] 6d f0 [2] 71 df }

  condition:
    any of them
}