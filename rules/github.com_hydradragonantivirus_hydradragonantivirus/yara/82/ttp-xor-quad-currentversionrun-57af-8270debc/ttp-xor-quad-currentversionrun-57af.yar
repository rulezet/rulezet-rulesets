rule TTP_XOR_QUAD_CurrentVersionRun_57af {
  strings:
    $key_57af = { 04 c0 [2] 20 ce [2] 0b e2 [2] 25 c0 [2] 31 db [2] 3e c1 [2] 20 dc [2] 22 dd [2] 39 db [2] 25 dc [2] 39 f3 }

  condition:
    any of them
}