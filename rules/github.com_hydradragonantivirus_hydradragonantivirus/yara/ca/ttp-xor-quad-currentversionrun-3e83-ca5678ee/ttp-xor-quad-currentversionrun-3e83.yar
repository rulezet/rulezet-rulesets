rule TTP_XOR_QUAD_CurrentVersionRun_3e83 {
  strings:
    $key_3e83 = { 6d ec [2] 49 e2 [2] 62 ce [2] 4c ec [2] 58 f7 [2] 57 ed [2] 49 f0 [2] 4b f1 [2] 50 f7 [2] 4c f0 [2] 50 df }

  condition:
    any of them
}