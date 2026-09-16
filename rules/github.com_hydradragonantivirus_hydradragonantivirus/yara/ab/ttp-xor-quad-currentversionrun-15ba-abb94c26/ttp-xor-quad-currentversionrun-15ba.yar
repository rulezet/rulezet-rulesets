rule TTP_XOR_QUAD_CurrentVersionRun_15ba {
  strings:
    $key_15ba = { 46 d5 [2] 62 db [2] 49 f7 [2] 67 d5 [2] 73 ce [2] 7c d4 [2] 62 c9 [2] 60 c8 [2] 7b ce [2] 67 c9 [2] 7b e6 }

  condition:
    any of them
}