rule TTP_XOR_QUAD_CurrentVersionRun_ff83 {
  strings:
    $key_ff83 = { ac ec [2] 88 e2 [2] a3 ce [2] 8d ec [2] 99 f7 [2] 96 ed [2] 88 f0 [2] 8a f1 [2] 91 f7 [2] 8d f0 [2] 91 df }

  condition:
    any of them
}