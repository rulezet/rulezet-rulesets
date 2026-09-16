rule TTP_XOR_QUAD_CurrentVersionRun_3083 {
  strings:
    $key_3083 = { 63 ec [2] 47 e2 [2] 6c ce [2] 42 ec [2] 56 f7 [2] 59 ed [2] 47 f0 [2] 45 f1 [2] 5e f7 [2] 42 f0 [2] 5e df }

  condition:
    any of them
}