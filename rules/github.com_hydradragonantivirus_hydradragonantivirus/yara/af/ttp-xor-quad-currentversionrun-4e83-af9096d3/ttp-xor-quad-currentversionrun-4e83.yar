rule TTP_XOR_QUAD_CurrentVersionRun_4e83 {
  strings:
    $key_4e83 = { 1d ec [2] 39 e2 [2] 12 ce [2] 3c ec [2] 28 f7 [2] 27 ed [2] 39 f0 [2] 3b f1 [2] 20 f7 [2] 3c f0 [2] 20 df }

  condition:
    any of them
}