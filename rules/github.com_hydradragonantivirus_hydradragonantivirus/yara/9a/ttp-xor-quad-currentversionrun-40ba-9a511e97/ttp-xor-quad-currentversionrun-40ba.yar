rule TTP_XOR_QUAD_CurrentVersionRun_40ba {
  strings:
    $key_40ba = { 13 d5 [2] 37 db [2] 1c f7 [2] 32 d5 [2] 26 ce [2] 29 d4 [2] 37 c9 [2] 35 c8 [2] 2e ce [2] 32 c9 [2] 2e e6 }

  condition:
    any of them
}