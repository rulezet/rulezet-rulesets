rule TTP_XOR_QUAD_CurrentVersionRun_0583 {
  strings:
    $key_0583 = { 56 ec [2] 72 e2 [2] 59 ce [2] 77 ec [2] 63 f7 [2] 6c ed [2] 72 f0 [2] 70 f1 [2] 6b f7 [2] 77 f0 [2] 6b df }

  condition:
    any of them
}