rule TTP_XOR_QUAD_CurrentVersionRun_eaaf {
  strings:
    $key_eaaf = { b9 c0 [2] 9d ce [2] b6 e2 [2] 98 c0 [2] 8c db [2] 83 c1 [2] 9d dc [2] 9f dd [2] 84 db [2] 98 dc [2] 84 f3 }

  condition:
    any of them
}