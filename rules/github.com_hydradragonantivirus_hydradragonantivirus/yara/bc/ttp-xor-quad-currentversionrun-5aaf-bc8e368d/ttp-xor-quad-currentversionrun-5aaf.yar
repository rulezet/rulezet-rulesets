rule TTP_XOR_QUAD_CurrentVersionRun_5aaf {
  strings:
    $key_5aaf = { 09 c0 [2] 2d ce [2] 06 e2 [2] 28 c0 [2] 3c db [2] 33 c1 [2] 2d dc [2] 2f dd [2] 34 db [2] 28 dc [2] 34 f3 }

  condition:
    any of them
}