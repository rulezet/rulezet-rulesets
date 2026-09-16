rule TTP_XOR_QUAD_CurrentVersionRun_7e83 {
  strings:
    $key_7e83 = { 2d ec [2] 09 e2 [2] 22 ce [2] 0c ec [2] 18 f7 [2] 17 ed [2] 09 f0 [2] 0b f1 [2] 10 f7 [2] 0c f0 [2] 10 df }

  condition:
    any of them
}