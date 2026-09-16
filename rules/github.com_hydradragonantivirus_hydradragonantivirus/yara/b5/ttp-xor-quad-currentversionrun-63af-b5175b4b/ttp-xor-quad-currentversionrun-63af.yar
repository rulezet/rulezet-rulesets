rule TTP_XOR_QUAD_CurrentVersionRun_63af {
  strings:
    $key_63af = { 30 c0 [2] 14 ce [2] 3f e2 [2] 11 c0 [2] 05 db [2] 0a c1 [2] 14 dc [2] 16 dd [2] 0d db [2] 11 dc [2] 0d f3 }

  condition:
    any of them
}