rule TTP_XOR_QUAD_CurrentVersionRun_4683 {
  strings:
    $key_4683 = { 15 ec [2] 31 e2 [2] 1a ce [2] 34 ec [2] 20 f7 [2] 2f ed [2] 31 f0 [2] 33 f1 [2] 28 f7 [2] 34 f0 [2] 28 df }

  condition:
    any of them
}