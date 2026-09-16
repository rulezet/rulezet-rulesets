rule TTP_XOR_QUAD_CurrentVersionRun_4f83 {
  strings:
    $key_4f83 = { 1c ec [2] 38 e2 [2] 13 ce [2] 3d ec [2] 29 f7 [2] 26 ed [2] 38 f0 [2] 3a f1 [2] 21 f7 [2] 3d f0 [2] 21 df }

  condition:
    any of them
}