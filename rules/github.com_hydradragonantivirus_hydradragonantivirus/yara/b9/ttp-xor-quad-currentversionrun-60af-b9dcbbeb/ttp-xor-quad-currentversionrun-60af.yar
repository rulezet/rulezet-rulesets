rule TTP_XOR_QUAD_CurrentVersionRun_60af {
  strings:
    $key_60af = { 33 c0 [2] 17 ce [2] 3c e2 [2] 12 c0 [2] 06 db [2] 09 c1 [2] 17 dc [2] 15 dd [2] 0e db [2] 12 dc [2] 0e f3 }

  condition:
    any of them
}