rule TTP_XOR_QUAD_CurrentVersionRun_70ba {
  strings:
    $key_70ba = { 23 d5 [2] 07 db [2] 2c f7 [2] 02 d5 [2] 16 ce [2] 19 d4 [2] 07 c9 [2] 05 c8 [2] 1e ce [2] 02 c9 [2] 1e e6 }

  condition:
    any of them
}