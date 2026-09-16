rule TTP_XOR_QUAD_CurrentVersionRun_20ba {
  strings:
    $key_20ba = { 73 d5 [2] 57 db [2] 7c f7 [2] 52 d5 [2] 46 ce [2] 49 d4 [2] 57 c9 [2] 55 c8 [2] 4e ce [2] 52 c9 [2] 4e e6 }

  condition:
    any of them
}