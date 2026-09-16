rule TTP_XOR_QUAD_CurrentVersionRun_2e83 {
  strings:
    $key_2e83 = { 7d ec [2] 59 e2 [2] 72 ce [2] 5c ec [2] 48 f7 [2] 47 ed [2] 59 f0 [2] 5b f1 [2] 40 f7 [2] 5c f0 [2] 40 df }

  condition:
    any of them
}