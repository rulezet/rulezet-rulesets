rule TTP_XOR_QUAD_CurrentVersionRun_30ba {
  strings:
    $key_30ba = { 63 d5 [2] 47 db [2] 6c f7 [2] 42 d5 [2] 56 ce [2] 59 d4 [2] 47 c9 [2] 45 c8 [2] 5e ce [2] 42 c9 [2] 5e e6 }

  condition:
    any of them
}