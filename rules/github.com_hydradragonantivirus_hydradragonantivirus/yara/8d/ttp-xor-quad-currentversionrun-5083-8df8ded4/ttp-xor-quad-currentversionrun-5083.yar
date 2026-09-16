rule TTP_XOR_QUAD_CurrentVersionRun_5083 {
  strings:
    $key_5083 = { 03 ec [2] 27 e2 [2] 0c ce [2] 22 ec [2] 36 f7 [2] 39 ed [2] 27 f0 [2] 25 f1 [2] 3e f7 [2] 22 f0 [2] 3e df }

  condition:
    any of them
}