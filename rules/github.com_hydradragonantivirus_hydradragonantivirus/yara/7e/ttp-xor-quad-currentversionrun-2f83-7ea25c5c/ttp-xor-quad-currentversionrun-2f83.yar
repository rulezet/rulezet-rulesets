rule TTP_XOR_QUAD_CurrentVersionRun_2f83 {
  strings:
    $key_2f83 = { 7c ec [2] 58 e2 [2] 73 ce [2] 5d ec [2] 49 f7 [2] 46 ed [2] 58 f0 [2] 5a f1 [2] 41 f7 [2] 5d f0 [2] 41 df }

  condition:
    any of them
}