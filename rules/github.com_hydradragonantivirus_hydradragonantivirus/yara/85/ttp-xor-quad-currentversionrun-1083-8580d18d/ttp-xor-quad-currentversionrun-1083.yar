rule TTP_XOR_QUAD_CurrentVersionRun_1083 {
  strings:
    $key_1083 = { 43 ec [2] 67 e2 [2] 4c ce [2] 62 ec [2] 76 f7 [2] 79 ed [2] 67 f0 [2] 65 f1 [2] 7e f7 [2] 62 f0 [2] 7e df }

  condition:
    any of them
}