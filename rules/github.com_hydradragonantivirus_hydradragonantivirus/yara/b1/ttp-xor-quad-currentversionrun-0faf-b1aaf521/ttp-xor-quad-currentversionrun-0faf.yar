rule TTP_XOR_QUAD_CurrentVersionRun_0faf {
  strings:
    $key_0faf = { 5c c0 [2] 78 ce [2] 53 e2 [2] 7d c0 [2] 69 db [2] 66 c1 [2] 78 dc [2] 7a dd [2] 61 db [2] 7d dc [2] 61 f3 }

  condition:
    any of them
}