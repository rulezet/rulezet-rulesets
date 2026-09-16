rule TTP_XOR_QUAD_CurrentVersionRun_6f83 {
  strings:
    $key_6f83 = { 3c ec [2] 18 e2 [2] 33 ce [2] 1d ec [2] 09 f7 [2] 06 ed [2] 18 f0 [2] 1a f1 [2] 01 f7 [2] 1d f0 [2] 01 df }

  condition:
    any of them
}