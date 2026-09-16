rule TTP_XOR_QUAD_CurrentVersionRun_60ba {
  strings:
    $key_60ba = { 33 d5 [2] 17 db [2] 3c f7 [2] 12 d5 [2] 06 ce [2] 09 d4 [2] 17 c9 [2] 15 c8 [2] 0e ce [2] 12 c9 [2] 0e e6 }

  condition:
    any of them
}