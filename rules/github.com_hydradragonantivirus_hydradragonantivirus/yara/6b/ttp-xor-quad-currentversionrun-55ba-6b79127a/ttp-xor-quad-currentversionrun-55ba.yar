rule TTP_XOR_QUAD_CurrentVersionRun_55ba {
  strings:
    $key_55ba = { 06 d5 [2] 22 db [2] 09 f7 [2] 27 d5 [2] 33 ce [2] 3c d4 [2] 22 c9 [2] 20 c8 [2] 3b ce [2] 27 c9 [2] 3b e6 }

  condition:
    any of them
}