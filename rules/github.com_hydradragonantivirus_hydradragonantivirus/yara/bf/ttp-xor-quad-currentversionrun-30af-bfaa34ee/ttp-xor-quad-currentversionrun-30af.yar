rule TTP_XOR_QUAD_CurrentVersionRun_30af {
  strings:
    $key_30af = { 63 c0 [2] 47 ce [2] 6c e2 [2] 42 c0 [2] 56 db [2] 59 c1 [2] 47 dc [2] 45 dd [2] 5e db [2] 42 dc [2] 5e f3 }

  condition:
    any of them
}