rule TTP_XOR_QUAD_CurrentVersionRun_10af {
  strings:
    $key_10af = { 43 c0 [2] 67 ce [2] 4c e2 [2] 62 c0 [2] 76 db [2] 79 c1 [2] 67 dc [2] 65 dd [2] 7e db [2] 62 dc [2] 7e f3 }

  condition:
    any of them
}