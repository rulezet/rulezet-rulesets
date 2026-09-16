rule TTP_XOR_QUAD_CurrentVersionRun_07af {
  strings:
    $key_07af = { 54 c0 [2] 70 ce [2] 5b e2 [2] 75 c0 [2] 61 db [2] 6e c1 [2] 70 dc [2] 72 dd [2] 69 db [2] 75 dc [2] 69 f3 }

  condition:
    any of them
}