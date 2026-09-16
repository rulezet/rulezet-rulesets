rule TTP_XOR_QUAD_CurrentVersionRun_1aaf {
  strings:
    $key_1aaf = { 49 c0 [2] 6d ce [2] 46 e2 [2] 68 c0 [2] 7c db [2] 73 c1 [2] 6d dc [2] 6f dd [2] 74 db [2] 68 dc [2] 74 f3 }

  condition:
    any of them
}