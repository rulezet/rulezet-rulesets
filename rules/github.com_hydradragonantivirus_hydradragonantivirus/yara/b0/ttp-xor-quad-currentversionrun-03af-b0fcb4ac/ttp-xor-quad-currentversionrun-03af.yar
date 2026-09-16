rule TTP_XOR_QUAD_CurrentVersionRun_03af {
  strings:
    $key_03af = { 50 c0 [2] 74 ce [2] 5f e2 [2] 71 c0 [2] 65 db [2] 6a c1 [2] 74 dc [2] 76 dd [2] 6d db [2] 71 dc [2] 6d f3 }

  condition:
    any of them
}