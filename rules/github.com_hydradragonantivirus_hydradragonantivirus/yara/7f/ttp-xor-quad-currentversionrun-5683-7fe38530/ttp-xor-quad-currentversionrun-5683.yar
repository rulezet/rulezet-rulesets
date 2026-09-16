rule TTP_XOR_QUAD_CurrentVersionRun_5683 {
  strings:
    $key_5683 = { 05 ec [2] 21 e2 [2] 0a ce [2] 24 ec [2] 30 f7 [2] 3f ed [2] 21 f0 [2] 23 f1 [2] 38 f7 [2] 24 f0 [2] 38 df }

  condition:
    any of them
}