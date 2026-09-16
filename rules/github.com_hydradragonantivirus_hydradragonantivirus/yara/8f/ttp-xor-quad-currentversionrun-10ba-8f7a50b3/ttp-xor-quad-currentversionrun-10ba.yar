rule TTP_XOR_QUAD_CurrentVersionRun_10ba {
  strings:
    $key_10ba = { 43 d5 [2] 67 db [2] 4c f7 [2] 62 d5 [2] 76 ce [2] 79 d4 [2] 67 c9 [2] 65 c8 [2] 7e ce [2] 62 c9 [2] 7e e6 }

  condition:
    any of them
}