rule TTP_XOR_QUAD_CurrentVersionRun_2083 {
  strings:
    $key_2083 = { 73 ec [2] 57 e2 [2] 7c ce [2] 52 ec [2] 46 f7 [2] 49 ed [2] 57 f0 [2] 55 f1 [2] 4e f7 [2] 52 f0 [2] 4e df }

  condition:
    any of them
}