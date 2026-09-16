rule TTP_XOR_QUAD_CurrentVersionRun_53af {
  strings:
    $key_53af = { 00 c0 [2] 24 ce [2] 0f e2 [2] 21 c0 [2] 35 db [2] 3a c1 [2] 24 dc [2] 26 dd [2] 3d db [2] 21 dc [2] 3d f3 }

  condition:
    any of them
}