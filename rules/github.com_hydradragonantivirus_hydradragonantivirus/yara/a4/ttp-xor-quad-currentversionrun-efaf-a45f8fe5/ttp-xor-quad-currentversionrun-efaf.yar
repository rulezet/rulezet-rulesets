rule TTP_XOR_QUAD_CurrentVersionRun_efaf {
  strings:
    $key_efaf = { bc c0 [2] 98 ce [2] b3 e2 [2] 9d c0 [2] 89 db [2] 86 c1 [2] 98 dc [2] 9a dd [2] 81 db [2] 9d dc [2] 81 f3 }

  condition:
    any of them
}